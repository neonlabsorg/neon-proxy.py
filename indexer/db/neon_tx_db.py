from __future__ import annotations

import logging
import pickle
from dataclasses import dataclass

from pydantic import Field
from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.evm_log_decoder import NeonTxEventModel
from common.neon.receipt_model import NeonTxReceiptModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel
from common.utils.pydantic import RootModel, BaseModel, UIntFromHexField
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


class NeonTxDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_transactions", _Record, key_list=("neon_sig", "block_slot"))

        self._select_by_tx_sig_query = DbQueryBody()
        self._select_by_nonce_query = DbQueryBody()
        self._select_by_block_query = DbQueryBody()
        self._select_by_index_query = DbQueryBody()
        self._select_base_fees_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        base_hdr_sql = DbSql(
            """;
            SELECT 
              {column_list},
              b.block_hash
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
        )

        select_by_tx_sig_sql = base_hdr_sql
        select_by_tx_sig_sql += DbSql(
            """
               AND b.is_active = True
             WHERE 
               a.neon_sig = {neon_tx_hash}
            """
        ).format(
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        select_by_nonce_sql = base_hdr_sql
        select_by_nonce_sql += DbSql(
            """
              AND b.is_active = True
            WHERE 
              a.from_addr = {sender}
              AND a.nonce = {nonce}
              AND a.v = ANY({v})
            """
        ).format(sender=DbSqlParam("sender"), nonce=DbSqlParam("nonce"), v=DbSqlParam("v"))

        select_by_block_sql = base_hdr_sql
        select_by_block_sql += DbSql(
            """
            WHERE 
               a.block_slot = {slot}
            ORDER BY 
               a.tx_idx ASC
            """
        ).format(
            slot=DbSqlParam("slot"),
        )

        select_by_index_sql = base_hdr_sql
        select_by_index_sql += DbSql(
            """
             WHERE 
               a.block_slot = {slot}
               AND a.tx_idx = {index}
            """
        ).format(
            slot=DbSqlParam("slot"),
            index=DbSqlParam("index"),
        )

        select_base_fees_sql = DbSql(
            """
            SELECT DISTINCT ON (a.block_slot)
              a.block_slot,
              a.average_base_fee,
              a.total_gas_used
            FROM (
              SELECT
                block_slot,
                AVG(Cast(max_fee_per_gas as Float) - Cast(max_priority_fee_per_gas as Float)) as average_base_fee,
                MAX(Cast(Cast(sum_gas_used as Float) as BIGINT)) as total_gas_used
              FROM
                {table_name} as t
              WHERE
                t.chain_id = {chain_id}
                AND t.max_fee_per_gas != ''
              GROUP BY
                block_slot
            ) a
            WHERE
              a.block_slot <= {latest_slot}
            ORDER BY
              a.block_slot DESC
            LIMIT {num_blocks}
            """
        ).format(
            table_name=self._table_name,
            chain_id=DbSqlParam("chain_id"),
            num_blocks=DbSqlParam("num_blocks"),
            latest_slot=DbSqlParam("latest_slot"),
        )

        (
            self._select_by_tx_sig_query,
            self._select_by_nonce_query,
            self._select_by_block_query,
            self._select_by_index_query,
            self._select_base_fees_query,
        ) = await self._db.sql_to_query(
            select_by_tx_sig_sql, select_by_nonce_sql, select_by_block_sql, select_by_index_sql, select_base_fees_sql
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [_Record.from_tx(tx.neon_tx, tx.neon_tx_rcpt) for b in block_list for tx in b.iter_done_neon_tx()]
        await self._insert_row_list(ctx, rec_list)

    async def get_tx_by_tx_hash(self, ctx: DbTxCtx, neon_tx_hash: EthTxHash) -> NeonTxMetaModel | None:
        rec = await self._fetch_one(
            ctx,
            self._select_by_tx_sig_query,
            _ByNeonTxSig(neon_tx_hash.to_string()),
            record_type=_RecordWithBlock,
        )
        return _RecordWithBlock.to_meta(rec)

    async def get_tx_by_sender_nonce(
        self,
        ctx: DbTxCtx,
        sender: NeonAccount,
        tx_nonce: int,
        inc_no_chain_id: bool,
    ) -> NeonTxMetaModel | None:
        v_list = [hex(sender.chain_id * 2 + 35), hex(sender.chain_id * 2 + 36)]
        if inc_no_chain_id:
            # before EIP-155: 0, 27, 28
            v_list.extend(["0x0", "0x1b", "0x1c"])

        rec = await self._fetch_one(
            ctx,
            self._select_by_nonce_query,
            _BySenderNonceV(sender.to_address(), hex(tx_nonce), v_list),
            record_type=_RecordWithBlock,
        )
        return _RecordWithBlock.to_meta(rec)

    async def get_tx_list_by_slot(self, ctx: DbTxCtx, slot: int) -> tuple[NeonTxMetaModel, ...]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_by_block_query,
            _ByBlock(slot),
            record_type=_RecordWithBlock,
        )
        return tuple([_RecordWithBlock.to_meta(rec) for rec in rec_list if rec is not None])

    async def get_tx_by_slot_tx_idx(self, ctx: DbTxCtx, slot: int, tx_idx: int) -> NeonTxMetaModel | None:
        rec = await self._fetch_one(
            ctx, self._select_by_index_query, _ByIndex(slot, tx_idx), record_type=_RecordWithBlock
        )
        return _RecordWithBlock.to_meta(rec)

    async def get_base_fees(
        self, ctx: DbTxCtx, chain_id: int, num_blocks: int, latest_slot: int
    ) -> list[BlockFeeGasData]:
        return await self._fetch_all(
            ctx,
            self._select_base_fees_query,
            _ByChainIdBlockCount(chain_id, num_blocks, latest_slot),
            record_type=BlockFeeGasData,
        )


# TODO: remove after converting all records
class _OldNeonTxEventModel(BaseModel):
    event_type: int = Field(1, validation_alias="neonEventType")
    is_hidden: bool = Field(False, validation_alias="neonIsHidden")

    neon_tx_hash: str = Field(validation_alias="transactionHash")

    address: str
    topic_list: list[str] = Field(validation_alias="topics")
    data: str

    sol_tx_sig: str = Field(validation_alias="neonSolHash")
    sol_ix_idx: UIntFromHexField = Field(validation_alias="neonIxIdx")
    sol_inner_ix_idx: UIntFromHexField | None = Field(validation_alias="neonInnerIxIdx")

    total_gas_used: int = 0
    total_step_cnt: int = 0
    is_reverted: bool = Field(False, validation_alias="neonIsReverted")
    event_level: UIntFromHexField = Field(0, validation_alias="neonEventLevel")
    event_order: UIntFromHexField = Field(0, validation_alias="neonEventOrder")

    block_hash: str = Field(validation_alias="blockHash")
    slot: UIntFromHexField = Field(validation_alias="blockNumber")
    neon_tx_idx: UIntFromHexField = Field(validation_alias="transactionIndex")
    block_log_idx: UIntFromHexField = Field(0, validation_alias="logIndex")
    neon_tx_log_idx: UIntFromHexField = Field(0, validation_alias="transactionLogIndex")


# TODO: remove after converting all records
class _OldNeonTxEventModelV2(BaseModel):
    event_type: int
    is_hidden: bool

    neon_tx_hash: str = Field(validation_alias="neon_sig")

    address: str
    topic_list: list[str]
    data: str

    sol_tx_sig: str = Field(validation_alias="sol_sig")
    sol_ix_idx: int = Field(validation_alias="idx")
    sol_inner_ix_idx: int | None = Field(validation_alias="inner_idx")

    total_gas_used: int = 0
    total_step_cnt: int = 0
    is_reverted: bool = False
    event_level: int = 0
    event_order: int = 0

    block_hash: str
    slot: int = Field(validation_alias="block_slot")
    neon_tx_idx: int = 0
    block_log_idx: int | None = None
    neon_tx_log_idx: int | None = None


# TODO: remove after converting all records
class _OldNeonTxEventModelV2List(RootModel):
    root: list[_OldNeonTxEventModelV2]


class _NeonTxEventModelList(RootModel):
    root: list[NeonTxEventModel]


@dataclass(frozen=True)
class _Record:
    sol_sig: str
    sol_ix_idx: int
    sol_ix_inner_idx: int
    block_slot: int

    tx_idx: int
    neon_sig: str

    tx_type: int
    chain_id: int | None  # absent for the legacy transactions.
    from_addr: str
    nonce: str
    to_addr: str | None
    contract: str | None
    value: str
    calldata: str
    gas_price: str
    max_fee_per_gas: str | None
    max_priority_fee_per_gas: str | None
    priority_fee_spent: str | None  # 0 for the legacy, total priority fee spent for dynamic gas neon transaction.
    gas_limit: str
    gas_used: str
    sum_gas_used: str
    v: str
    r: str
    s: str

    status: str

    is_canceled: bool
    is_completed: bool

    logs: bytes | None

    @classmethod
    def from_tx(cls, neon_tx: NeonTxModel, neon_rcpt: NeonTxReceiptModel) -> Self:
        return cls(
            sol_sig=neon_rcpt.sol_tx_sig.to_string(),
            sol_ix_idx=neon_rcpt.sol_ix_idx,
            sol_ix_inner_idx=neon_rcpt.sol_inner_ix_idx,
            block_slot=neon_rcpt.slot,
            tx_idx=neon_rcpt.neon_tx_idx,
            neon_sig=neon_tx.neon_tx_hash.to_string(),
            tx_type=neon_tx.tx_type,
            chain_id=neon_tx.tx_chain_id,
            from_addr=neon_tx.from_address.to_string(),
            nonce=hex(neon_tx.nonce),
            to_addr=neon_tx.to_address.to_string(None),
            contract=neon_tx.contract.to_string(None),
            value=hex(neon_tx.value),
            calldata=neon_tx.call_data.to_string(),
            gas_price=hex(NeonTxMetaModel(neon_tx=neon_tx, neon_tx_rcpt=neon_rcpt).effective_gas_price),
            max_fee_per_gas=hex(neon_tx.max_fee_per_gas) if neon_tx.max_fee_per_gas is not None else None,
            max_priority_fee_per_gas=(
                hex(neon_tx.max_priority_fee_per_gas) if neon_tx.max_priority_fee_per_gas is not None else None
            ),
            priority_fee_spent=hex(neon_rcpt.priority_fee_spent) if neon_rcpt.priority_fee_spent else None,
            gas_limit=hex(neon_tx.gas_limit),
            gas_used=hex(neon_rcpt.total_gas_used),
            sum_gas_used=hex(neon_rcpt.sum_gas_used),
            v=hex(neon_tx.v),
            r=hex(neon_tx.r),
            s=hex(neon_tx.s),
            status=hex(neon_rcpt.status),
            is_canceled=neon_rcpt.is_canceled,
            is_completed=neon_rcpt.is_completed,
            logs=cls._encode_event_list(neon_rcpt),
        )

    @staticmethod
    def _encode_event_list(neon_rcpt: NeonTxReceiptModel) -> bytes | None:
        if not neon_rcpt.event_list:
            return None
        return bytes(_NeonTxEventModelList(list(neon_rcpt.event_list)).to_json(), "utf-8")


@dataclass(frozen=True)
class _RecordWithBlock(_Record):
    block_hash: str

    def to_meta(self) -> NeonTxMetaModel | None:
        if not self:
            return None

        params = dict(
            tx_type=self.tx_type,
            tx_chain_id=None if self.chain_id == 0 else self.chain_id,
            neon_tx_hash=self.neon_sig,
            from_address=self.from_addr,
            to_address=self.to_addr,
            contract=self.contract,
            nonce=self.nonce,
            gas_price_legacy=self.gas_price,
            max_fee_per_gas=self.max_fee_per_gas,
            max_priority_fee_per_gas=self.max_priority_fee_per_gas,
            gas_limit=self.gas_limit,
            value=self.value,
            call_data=self.calldata,
            v=self.v,
            r=self.r,
            s=self.s,
        )
        # TODO EIP1559: introduce blob field which stores rlp and construct via from_raw(rlp).
        # Alternatively, allow non-frozen model and modify it in the model_post_init.
        NeonTxModel.pop_ctr_params(params)
        neon_tx = NeonTxModel(**params)

        neon_tx_rcpt = NeonTxReceiptModel(
            slot=self.block_slot,
            block_hash=self.block_hash,
            sol_tx_sig=self.sol_sig,
            sol_ix_idx=self.sol_ix_idx,
            sol_inner_ix_idx=self.sol_ix_inner_idx,
            neon_tx_idx=self.tx_idx,
            status=self.status,
            total_gas_used=self.gas_used,
            sum_gas_used=self.sum_gas_used,
            priority_fee_spent=self.priority_fee_spent if self.priority_fee_spent else 0,
            is_completed=self.is_completed,
            is_canceled=self.is_canceled,
            event_list=self._decode_event_list(self.logs),
        )

        return NeonTxMetaModel(neon_tx=neon_tx, neon_tx_rcpt=neon_tx_rcpt)

    @staticmethod
    def _decode_event_list(value: bytes) -> list[NeonTxEventModel]:
        try:
            if not value:
                return list()

            if value.startswith(b"[") and value.endswith(b"]"):
                json_data = str(value, "utf-8")
                if "sol_sig" in json_data:
                    # TODO: remove after converting all records
                    old_event_list = _OldNeonTxEventModelV2List.from_json(json_data).root
                    event_list = [NeonTxEventModel.from_dict(event.to_dict()) for event in old_event_list]
                    return event_list
                else:
                    return _NeonTxEventModelList.from_json(json_data).root

            # TODO: remove after converting all records
            value_list = pickle.loads(value)
            event_list = [
                NeonTxEventModel.from_dict(_OldNeonTxEventModel.from_dict(value).to_dict()) for value in value_list
            ]
            return event_list

        except BaseException as exc:
            _LOG.warning("cannot decode event list %s", value, exc_info=exc)
            return list()


@dataclass(frozen=True)
class BlockFeeGasData:
    block_slot: int
    average_base_fee: float
    total_gas_used: int


@dataclass(frozen=True)
class _ByNeonTxSig:
    neon_tx_hash: str


@dataclass(frozen=True)
class _BySenderNonceV:
    sender: str
    nonce: str
    v: list[str]


@dataclass(frozen=True)
class _ByBlock:
    slot: int


@dataclass(frozen=True)
class _ByIndex:
    slot: int
    index: int


@dataclass(frozen=True)
class _ByChainIdBlockCount:
    chain_id: int
    num_blocks: int
    latest_slot: int

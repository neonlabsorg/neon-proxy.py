from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence, Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.ethereum.transaction import EthTxType
from common.neon.address import NeonAddress
from common.neon.evm_log_decoder import NeonTxEventModel
from common.neon.receipt_model import NeonTxReceiptModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel
from common.utils.format import if_value, if_none
from common.utils.pydantic import RootModel
from .neon_skd_tx_relation_db import NeonSkdTxRelationDb, NeonSkdTxRelationInfo
from .neon_skd_tx_sig_db import NeonSkdTxSigDb, NeonSkdTxSigInfo
from .neon_tx_db_old import NeonTxDbOld
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


class NeonTxDb(HistoryDbTable):
    def __init__(self, db: DbConnection, skd_tx_sig_db: NeonSkdTxSigDb, skd_tx_relation_db: NeonSkdTxRelationDb):
        super().__init__(db, "neon_compact_transactions", _Record, key_list=("neon_sig", "block_slot"))

        self._skd_tx_sig_db = skd_tx_sig_db
        self._skd_tx_relation_db = skd_tx_relation_db

        # TODO: remove
        self._old_neon_tx_db = NeonTxDbOld(db)

        self._select_by_tx_hash_query = DbQueryBody()
        self._select_by_nonce_query = DbQueryBody()
        self._select_by_block_query = DbQueryBody()
        self._select_by_index_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()
        # TODO: remove
        await self._old_neon_tx_db.start()

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

        select_by_tx_hash_sql = base_hdr_sql
        select_by_tx_hash_sql += DbSql(
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
              a.payer = {payer}
              AND a.nonce = {nonce}
              AND a.index = {index}
              AND a.chain_id = ANY({chain_id})
            """
        ).format(
            payer=DbSqlParam("payer"),
            nonce=DbSqlParam("nonce"),
            index=DbSqlParam("index"),
            chain_id=DbSqlParam("chain_id"),
        )

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

        (
            self._select_by_tx_hash_query,
            self._select_by_nonce_query,
            self._select_by_block_query,
            self._select_by_index_query,
        ) = await self._db.sql_to_query(
            select_by_tx_hash_sql,
            select_by_nonce_sql,
            select_by_block_sql,
            select_by_index_sql,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        rec_list = [_Record.from_tx(tx.neon_tx, tx.neon_tx_rcpt) for b in block_list for tx in b.iter_done_neon_tx()]
        await self._insert_row_list(ctx, rec_list)

    async def get_tx_by_tx_hash(self, ctx: DbTxCtx, neon_tx_hash: EthTxHash) -> NeonTxMetaModel | None:
        rec = await self._fetch_one(
            ctx,
            self._select_by_tx_hash_query,
            _ByNeonTxHash(neon_tx_hash.to_string()),
            record_type=_RecordWithBlock,
        )
        if rec:
            skd_sig_dict, skd_rel_dict = await self._get_skd_sig_list(ctx, rec)
            return _RecordWithBlock.to_clean_copy(rec, skd_sig_dict, skd_rel_dict)

        # TODO: remove
        return await self._old_neon_tx_db.get_tx_by_tx_hash(ctx, neon_tx_hash)

    async def get_tx_by_sender_nonce(
        self,
        ctx: DbTxCtx,
        sender: NeonAddress,
        tx_nonce: int,
        tx_index: int,
        inc_no_chain_id: bool,
    ) -> NeonTxMetaModel | None:
        chain_list = [sender.chain_id]
        if inc_no_chain_id:
            chain_list.append(0)

        rec = await self._fetch_one(
            ctx,
            self._select_by_nonce_query,
            _BySenderNonceChain(sender.to_address(), tx_nonce, tx_index, chain_list),
            record_type=_RecordWithBlock,
        )
        if rec:
            skd_sig_dict, skd_rel_dict = await self._get_skd_sig_list(ctx, rec)
            return _RecordWithBlock.to_clean_copy(rec, skd_sig_dict, skd_rel_dict)
        if tx_index != 0:
            return None

        # TODO: remove
        return await self._old_neon_tx_db.get_tx_by_sender_nonce(ctx, sender, tx_nonce, inc_no_chain_id)

    async def get_tx_list_by_slot(self, ctx: DbTxCtx, slot: int) -> Sequence[NeonTxMetaModel]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_by_block_query,
            _ByBlock(slot),
            record_type=_RecordWithBlock,
        )
        if rec_list:
            # fmt: off
            skd_sig_dict, skd_rel_dict = await self._get_skd_sig_list(ctx, rec_list)
            return tuple([
                _RecordWithBlock.to_clean_copy(rec, skd_sig_dict, skd_rel_dict)
                for rec in rec_list
                if rec is not None
            ])
            # fmt: on

        # TODO: remove
        return await self._old_neon_tx_db.get_tx_list_by_slot(ctx, slot)

    async def get_tx_by_slot_tx_idx(self, ctx: DbTxCtx, slot: int, tx_idx: int) -> NeonTxMetaModel | None:
        rec = await self._fetch_one(
            ctx,
            self._select_by_index_query,
            _ByIndex(slot, tx_idx),
            record_type=_RecordWithBlock,
        )
        if rec:
            skd_sig_dict, skd_rel_dict = await self._get_skd_sig_list(ctx, rec)
            return _RecordWithBlock.to_clean_copy(rec, skd_sig_dict, skd_rel_dict)

        # TODO: remove
        return await self._old_neon_tx_db.get_tx_by_slot_tx_idx(ctx, slot, tx_idx)

    async def _get_skd_sig_list(
        self,
        ctx: DbTxCtx,
        rec_list: _RecordWithBlock | Sequence[_RecordWithBlock],
    ) -> tuple[
        dict[EthTxHash, NeonSkdTxSigInfo],
        dict[EthTxHash, NeonSkdTxRelationInfo],
    ]:
        if not isinstance(rec_list, (tuple, list,)):
            rec_list = tuple([rec_list])

        # fmt: off
        tx_hash_list = tuple([
            EthTxHash.from_raw(rec.neon_sig)
            for rec in rec_list
            if rec and EthTxType.is_scheduled_tx(rec.rlp_body)
        ])
        # fmt: on

        if not tx_hash_list:
            return dict(), dict()

        return await asyncio.gather(
            self._skd_tx_sig_db.get_skd_tx_sig_dict(ctx, tx_hash_list),
            self._skd_tx_relation_db.get_skd_tx_relation_dict(ctx, tx_hash_list),
        )


class _NeonTxEventModelList(RootModel):
    root: list[NeonTxEventModel]


@dataclass(frozen=True)
class _Record:
    neon_sig: str

    payer: str
    nonce: Decimal
    index: int
    chain_id: int

    sol_sig: str
    sol_ix_idx: int
    sol_ix_inner_idx: int

    block_slot: int
    tx_idx: int

    base_fee_per_gas: Decimal
    base_fee_used: int
    priority_fee_per_gas: Decimal
    priority_fee_used: int
    gas_used: int
    sum_gas_used: int

    status: int
    is_canceled: bool

    rlp_body: bytes
    logs: str | None

    @classmethod
    def from_tx(cls, neon_tx: NeonTxModel, neon_rcpt: NeonTxReceiptModel) -> Self:
        return cls(
            neon_sig=neon_tx.neon_tx_hash.to_string(),
            payer=neon_tx.payer.to_string(),
            nonce=neon_tx.nonce,
            index=neon_tx.index,
            chain_id=neon_tx.chain_id,
            sol_sig=neon_rcpt.sol_tx_sig.to_string(),
            sol_ix_idx=neon_rcpt.sol_ix_idx,
            sol_ix_inner_idx=if_none(neon_rcpt.sol_inner_ix_idx, -1),
            block_slot=neon_rcpt.slot,
            tx_idx=neon_rcpt.neon_tx_idx,
            base_fee_per_gas=Decimal(neon_tx.base_fee_per_gas),
            base_fee_used=neon_rcpt.base_fee_used,
            priority_fee_per_gas=Decimal(neon_tx.max_priority_fee_per_gas),
            priority_fee_used=neon_rcpt.priority_fee_used,
            gas_used=neon_rcpt.total_gas_used,
            sum_gas_used=neon_rcpt.sum_gas_used,
            status=neon_rcpt.status,
            is_canceled=neon_rcpt.is_canceled,
            rlp_body=neon_tx.to_rlp_tx(),
            logs=cls._encode_event_list(neon_rcpt),
        )

    @staticmethod
    def _encode_event_list(neon_rcpt: NeonTxReceiptModel) -> str | None:
        if not neon_rcpt.event_list:
            return None
        return _NeonTxEventModelList(root=list(neon_rcpt.event_list)).to_json()


@dataclass(frozen=True)
class _RecordWithBlock(_Record):
    block_hash: str

    @staticmethod
    def to_clean_copy(
        self: _RecordWithBlock,
        skd_sig_dict: dict[EthTxHash, NeonSkdTxSigInfo],
        skd_rel_dict: dict[EthTxHash, NeonSkdTxRelationInfo],
    ) -> NeonTxMetaModel | None:
        if not self:
            return None

        neon_tx_hash = EthTxHash.from_raw(self.neon_sig)
        skd_sig = skd_sig_dict.get(neon_tx_hash, NeonSkdTxSigInfo.default())
        skd_rel = skd_rel_dict.get(neon_tx_hash, NeonSkdTxRelationInfo.default())

        param_dict = dict(
            rlp_tx=self.rlp_body,
            sol_skd_tx_sig=skd_sig.sol_sig,
            sol_skd_payer=skd_sig.sol_payer,
        )
        neon_tx = NeonTxModel.from_raw(param_dict)

        neon_tx_rcpt = NeonTxReceiptModel(
            slot=self.block_slot,
            block_hash=self.block_hash,
            sol_tx_sig=self.sol_sig,
            sol_ix_idx=self.sol_ix_idx,
            sol_inner_ix_idx=if_value(self.sol_ix_inner_idx, -1, None),
            neon_tx_idx=self.tx_idx,
            status=self.status,
            total_gas_used=self.gas_used,
            sum_gas_used=self.sum_gas_used,
            priority_fee_used=self.priority_fee_used,
            base_fee_used=self.base_fee_used,
            is_canceled=self.is_canceled,
            event_list=self._decode_event_list(self.logs),
            parent_tx_list=list(skd_rel.parent_tx_hash_set),
            child_tx_list=list(skd_rel.child_tx_hash_set),
        )

        return NeonTxMetaModel(neon_tx=neon_tx, neon_tx_rcpt=neon_tx_rcpt)

    @staticmethod
    def _decode_event_list(value: str) -> list[NeonTxEventModel]:
        try:
            if not value:
                return list()

            return _NeonTxEventModelList.from_json(value).root

        except BaseException as exc:
            _LOG.warning("cannot decode event list %s", value, exc_info=exc)
            return list()


@dataclass(frozen=True)
class _ByNeonTxHash:
    neon_tx_hash: str


@dataclass(frozen=True)
class _BySenderNonceChain:
    payer: str
    nonce: int
    index: int
    chain_id: list[int]


@dataclass(frozen=True)
class _ByBlock:
    slot: int


@dataclass(frozen=True)
class _ByIndex:
    slot: int
    index: int

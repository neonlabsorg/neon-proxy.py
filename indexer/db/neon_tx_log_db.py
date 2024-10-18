from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlComposable, DbSqlIdent, DbSqlParam
from common.ethereum.hash import EthHash32, EthAddress
from common.neon.evm_log_decoder import NeonTxEventModel
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo


class NeonTxLogDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_transaction_logs", _Record, key_list=("block_slot", "tx_hash", "tx_log_idx"))
        self._topic_column_list = ("log_topic1", "log_topic2", "log_topic3", "log_topic4")

        self._select_sql = DbSql(
            """;
            SELECT
              {column_list},
              b.block_hash
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            WHERE
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [
            _Record.from_event(event)
            for block in block_list
            for tx in block.iter_done_neon_tx()
            for event in tx.neon_tx_rcpt.event_list
            if (not event.is_hidden) and event.topic_list
        ]
        await self._insert_row_list(ctx, rec_list)

    async def get_event_list(
        self,
        ctx: DbTxCtx,
        from_slot: int | None,
        to_slot: int | None,
        address_list: tuple[EthAddress, ...],
        topic_list: tuple[tuple[EthHash32, ...], ...],
    ) -> tuple[NeonTxEventModel, ...]:

        query_list: list[DbSqlComposable] = [DbSql("1 = 1")]
        param_dict = dict()

        if from_slot is not None:
            query_list.append(DbSql("a.block_slot >= {}").format(DbSqlParam("from_slot")))
            param_dict["from_slot"] = from_slot

        if to_slot is not None:
            query_list.append(DbSql("a.block_slot <= {}").format(DbSqlParam("to_slot")))
            param_dict["to_slot"] = to_slot

        for topic_name, topic_value in zip(self._topic_column_list, topic_list):
            if topic_value:
                query_list.append(DbSql("a.{} = ANY({})").format(DbSqlIdent(topic_name), DbSqlParam(topic_name)))
                param_dict[topic_name] = [t.to_string() for t in topic_value]

        if topic_list:
            query_list.append(DbSql("a.log_topic_cnt >= ") + DbSqlParam("topic_cnt"))
            param_dict["topic_cnt"] = len(topic_list)

        if address_list:
            query_list.append(DbSql("a.address = ANY({})").format(DbSqlParam("address_list")))
            param_dict["address_list"] = [a.to_string() for a in address_list]

        select_sql = self._select_sql
        select_sql += DbSql(" AND ").join(query_list)
        select_sql += DbSql(" ORDER BY a.block_slot DESC, a.log_idx DESC LIMIT 1000")

        rec_list = await self._fetch_all(ctx, select_sql, param_dict, record_type=_RecordWithBlock)
        return tuple([rec.to_event() for rec in reversed(rec_list)])


@dataclass(frozen=True)
class _Record:
    address: str
    block_slot: int

    tx_hash: str
    tx_idx: int
    tx_log_idx: int
    log_idx: int

    log_topic1: str
    log_topic2: str | None
    log_topic3: str | None
    log_topic4: str | None
    log_topic_cnt: int

    log_data: str

    event_order: int
    event_level: int

    sol_sig: str
    idx: int
    inner_idx: int | None

    @classmethod
    def from_event(cls, event: NeonTxEventModel) -> Self:
        def _get_topic(_idx: int) -> str:
            return event.topic_list[_idx].to_string() if _idx < len(event.topic_list) else None

        return cls(
            log_topic1=_get_topic(0),
            log_topic2=_get_topic(1),
            log_topic3=_get_topic(2),
            log_topic4=_get_topic(3),
            log_topic_cnt=len(event.topic_list),
            log_data=event.data.to_string(),
            block_slot=event.slot,
            tx_hash=event.neon_tx_hash.to_string(),
            tx_idx=event.neon_tx_idx,
            tx_log_idx=event.neon_tx_log_idx,
            log_idx=event.block_log_idx,
            address=event.address.to_string(),
            event_order=event.event_order,
            event_level=event.event_level,
            sol_sig=event.sol_tx_sig.to_string(),
            idx=event.sol_ix_idx,
            inner_idx=event.sol_inner_ix_idx,
        )


@dataclass(frozen=True)
class _RecordWithBlock(_Record):
    block_hash: str

    def to_event(self) -> NeonTxEventModel:
        topic_list = [self.log_topic1, self.log_topic2, self.log_topic3, self.log_topic4][: self.log_topic_cnt]
        return NeonTxEventModel(
            neon_tx_hash=self.tx_hash,
            address=self.address,
            topic_list=topic_list,
            data=self.log_data,
            sol_tx_sig=self.sol_sig,
            sol_ix_idx=self.idx,
            sol_inner_ix_idx=self.inner_idx,
            event_level=self.event_level,
            event_order=self.event_order,
            slot=self.block_slot,
            neon_tx_idx=self.tx_idx,
            block_log_idx=self.log_idx,
            neon_tx_log_idx=self.tx_log_idx,
            block_hash=self.block_hash,
            # default:
            event_type=NeonTxEventModel.Type.Log,
            is_hidden=False,
            is_reverted=False,
            total_gas_used=0,
            total_step_cnt=0,
        )

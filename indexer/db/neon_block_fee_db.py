from __future__ import annotations

from dataclasses import dataclass

from common.db.db_connect import DbConnection, DbSql, DbSqlParam, DbTxCtx, DbQueryBody
from common.neon.block import NeonBlockBaseFeeInfo
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo


class NeonBlockFeeDB(HistoryDbTable):
    def __init__(self, db: DbConnection, def_chain_id: int = 0):
        super().__init__(db, "neon_block_fees", _Record, key_list=("block_slot", "chain_id"))
        self._def_chain_id = def_chain_id
        self._base_fee_list_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        base_fee_list_sql = DbSql(
            """;
            SELECT 
                {column_list}
            FROM 
                {table_name} AS a
            WHERE
                a.block_slot < {latest_slot}
                AND a.chain_id = {chain_id}
            ORDER BY
                a.block_slot DESC
            LIMIT 
                {block_cnt}
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            latest_slot=DbSqlParam("latest_slot"),
            chain_id=DbSqlParam("chain_id"),
            block_cnt=DbSqlParam("block_cnt"),
        )

        self._base_fee_list_query = await self._db.sql_to_query(base_fee_list_sql)

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list: list[_Record] = list()

        for block in block_list:
            chain_fee_dict: dict[int, int] = dict()
            for tx in block.iter_done_neon_tx():
                if not tx.neon_tx.is_dynamic_gas_tx:
                    tx_base_fee = tx.neon_tx.gas_price_legacy
                elif tx.neon_tx.max_fee_per_gas == tx.neon_tx.max_priority_fee_per_gas:
                    tx_base_fee = tx.neon_tx.max_fee_per_gas
                else:
                    tx_base_fee = tx.neon_tx.max_fee_per_gas - tx.neon_tx.max_priority_fee_per_gas

                if not tx_base_fee:
                    continue

                chain_id = tx.neon_tx.chain_id or self._def_chain_id
                chain_base_fee: int = chain_fee_dict.get(chain_id, 0)
                chain_fee_dict[chain_id] = chain_base_fee + tx_base_fee

            for chain_id, base_fee in chain_fee_dict.items():
                rec = _Record(block_slot=block.slot, chain_id=chain_id, base_fee=hex(base_fee))
                rec_list.append(rec)

        await self._insert_row_list(ctx, rec_list)

    async def get_block_base_fee_list(
        self, ctx: DbTxCtx, chain_id: int, block_cnt: int, latest_slot: int
    ) -> tuple[NeonBlockBaseFeeInfo, ...]:
        rec_list = await self._fetch_all(
            ctx,
            self._base_fee_list_query,
            _ByChainId(chain_id=chain_id, latest_slot=latest_slot, block_cnt=block_cnt),
            record_type=_Record,
        )
        return tuple([rec.to_neon_block() for rec in rec_list])


@dataclass(frozen=True)
class _Record:
    block_slot: int
    chain_id: int
    base_fee: str

    def to_neon_block(self) -> NeonBlockBaseFeeInfo:
        return NeonBlockBaseFeeInfo(
            slot=self.block_slot,
            chain_id=self.chain_id,
            base_fee=int(self.base_fee, 16),
        )


@dataclass(frozen=True)
class _ByChainId:
    chain_id: int
    latest_slot: int
    block_cnt: int
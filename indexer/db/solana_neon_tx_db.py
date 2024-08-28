from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbQueryBody, DbSqlParam
from common.ethereum.hash import EthTxHash
from common.neon.transaction_decoder import SolNeonTxIxMetaInfo, SolNeonTxIxMetaModel
from common.solana.signature import SolTxSig, SolTxSigSlotInfo
from common.solana.transaction_decoder import SolTxCostModel
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo


class SolNeonTxDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "solana_neon_transactions", _Record, ("sol_sig", "block_slot", "idx", "inner_idx"))
        self._select_sig_list_query = DbQueryBody()
        self._select_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()
        select_sig_list_sql = DbSql(
            """;
            SELECT
                a.block_slot,
                a.sol_sig as sol_tx_sig
            FROM 
                {table_name} AS a
            INNER JOIN 
                {block_table_name} AS b
                ON b.block_slot = a.block_slot
                AND b.is_active = True
            WHERE 
                a.neon_sig = {neon_tx_hash}
            ORDER BY 
                a.block_slot, a.neon_total_gas_used, a.sol_sig, a.idx, a.inner_idx
            """
        ).format(
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        select_sql = DbSql(
            """;
            SELECT DISTINCT 
                {column_list},
                c.operator, 
                c.sol_spent
            FROM 
                {table_name} a
            INNER JOIN 
                {block_table_name} AS b
                ON b.block_slot = a.block_slot
                AND b.is_active = True
            INNER JOIN 
                {cost_table_name} AS c
                ON c.sol_sig = a.sol_sig
            WHERE 
                a.neon_sig = {neon_tx_hash}
            ORDER BY 
                a.block_slot, a.neon_total_gas_used, a.sol_sig, a.idx, a.inner_idx
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            block_table_name=self._block_table_name,
            cost_table_name=self._cost_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        self._select_sig_list_query, self._select_query = await self._db.sql_to_query(select_sig_list_sql, select_sql)

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [_Record.from_sol_neon_ix(ix) for block in block_list for ix in block.iter_sol_neon_ix()]
        await self._insert_row_list(ctx, rec_list)

    async def get_sol_tx_sig_list_by_neon_tx_hash(
        self,
        ctx: DbTxCtx,
        neon_tx_hash: EthTxHash,
    ) -> tuple[SolTxSigSlotInfo, ...]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_sig_list_query,
            _ByNeonTxSig(neon_tx_hash.to_string()),
            record_type=_SolTxSigSlot,
        )

        done_sig_set: set[str] = set()
        sol_sig_list: list[SolTxSigSlotInfo] = list()
        for rec in rec_list:
            if rec.sol_tx_sig in done_sig_set:
                continue

            done_sig_set.add(rec.sol_tx_sig)
            sol_sig_list.append(SolTxSigSlotInfo(rec.block_slot, SolTxSig.from_raw(rec.sol_tx_sig)))
        return tuple(sol_sig_list)

    async def get_sol_ix_list_by_neon_tx_hash(
        self,
        ctx: DbTxCtx,
        neon_tx_hash: EthTxHash,
    ) -> tuple[SolNeonTxIxMetaModel, ...]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_query,
            _ByNeonTxSig(neon_tx_hash.to_string()),
            record_type=_RecordWithCost,
        )
        return tuple([rec.to_sol_neon_ix() for rec in rec_list])


@dataclass(frozen=True)
class _Record:
    sol_sig: str
    block_slot: int
    idx: int
    inner_idx: int | None
    ix_code: int
    is_success: bool
    neon_sig: str
    neon_miner: str
    neon_step_cnt: int
    neon_total_step_cnt: int
    neon_gas_used: int
    neon_total_gas_used: int
    max_heap_size: int
    used_heap_size: int
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int

    @classmethod
    def from_sol_neon_ix(cls, sol_neon_ix: SolNeonTxIxMetaInfo) -> Self:
        return cls(
            sol_sig=sol_neon_ix.sol_tx_sig.to_string(),
            block_slot=sol_neon_ix.slot,
            idx=sol_neon_ix.sol_ix_idx,
            inner_idx=sol_neon_ix.sol_inner_ix_idx,
            ix_code=sol_neon_ix.neon_ix_code,
            is_success=sol_neon_ix.is_success,
            neon_sig=sol_neon_ix.neon_tx_hash.to_string(),
            neon_miner=sol_neon_ix.neon_tx_ix_miner.to_string(),
            neon_step_cnt=sol_neon_ix.neon_tx_ix_step_cnt,
            neon_total_step_cnt=sol_neon_ix.neon_total_step_cnt,
            neon_gas_used=sol_neon_ix.neon_tx_ix_gas_used,
            neon_total_gas_used=sol_neon_ix.neon_total_gas_used,
            max_heap_size=sol_neon_ix.heap_size,
            used_heap_size=sol_neon_ix.used_heap_size,
            max_bpf_cycle_cnt=sol_neon_ix.cu_limit,
            used_bpf_cycle_cnt=sol_neon_ix.used_cu_limit,
        )


@dataclass(frozen=True)
class _RecordWithCost(_Record):
    operator: str
    sol_spent: int

    def to_sol_neon_ix(self) -> SolNeonTxIxMetaModel:
        inner_ix_idx = None if (self.inner_idx is None) or (self.inner_idx < 0) else self.inner_idx

        return SolNeonTxIxMetaModel(
            sol_tx_sig=self.sol_sig,
            slot=self.block_slot,
            sol_ix_idx=self.idx,
            sol_inner_ix_idx=inner_ix_idx,
            is_success=self.is_success,
            neon_tx_hash=self.neon_sig,
            neon_ix_code=self.ix_code,
            neon_tx_ix_miner=self.neon_miner,
            neon_step_cnt=self.neon_step_cnt,
            neon_total_step_cnt=self.neon_total_step_cnt,
            neon_gas_used=self.neon_gas_used,
            neon_total_gas_used=self.neon_total_gas_used,
            heap_size=self.max_heap_size,
            used_heap_size=self.used_heap_size,
            cu_limit=self.max_bpf_cycle_cnt,
            used_cu_limit=self.used_bpf_cycle_cnt,
            sol_tx_cost=SolTxCostModel(
                sol_tx_sig=self.sol_sig,
                slot=self.block_slot,
                is_success=self.is_success,
                sol_signer=self.operator,
                sol_expense=self.sol_spent,
            ),
        )


@dataclass(frozen=True)
class _ByNeonTxSig:
    neon_tx_hash: str


@dataclass(frozen=True)
class _SolTxSigSlot:
    block_slot: int
    sol_tx_sig: str

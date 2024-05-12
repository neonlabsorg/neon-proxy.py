from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbSql, DbSqlParam, DbTxCtx, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.transaction_decoder import SolNeonAltIxModel
from common.solana.signature import SolTxSig
from common.solana.transaction_decoder import SolTxCostModel
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo


class SolAltTxDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "solana_alt_transactions", _Record, ("sol_sig", "block_slot", "idx", "inner_idx"))

        self._select_query = DbQueryBody()
        self._select_sig_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_sql = DbSql(
            """;
            SELECT DISTINCT 
              {column_list},
              c.operator, c.sol_spent
            FROM 
              {table_name} a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
            INNER JOIN 
              {cost_table_name} AS c
              ON c.sol_sig = a.sol_sig
            WHERE 
              a.neon_sig = {neon_tx_hash}
            ORDER BY 
              a.block_slot, a.sol_sig, a.idx, a.inner_idx
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            cost_table_name=self._cost_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        select_sig_sql = DbSql(
            """;
            SELECT DISTINCT 
                a.block_slot, 
                a.sol_sig
            FROM 
                {table_name} AS a
            INNER JOIN 
                {block_table_name} AS b
                ON b.block_slot = a.block_slot
                AND b.is_active = True
            WHERE 
                a.neon_sig = {neon_tx_hash}
            ORDER BY 
                a.block_slot, a.sol_sig
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        self._select_query, self._select_sig_query = await self._db.sql_to_query(select_sql, select_sig_sql)

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [_Record.from_alt_model(sol_alt) for block in block_list for sol_alt in block.iter_sol_alt_ix()]
        await self._insert_row_list(ctx, rec_list)

    async def get_alt_ix_list_by_neon_tx_hash(
        self,
        ctx: DbTxCtx,
        neon_tx_hash: EthTxHash,
    ) -> tuple[SolNeonAltIxModel, ...]:
        rec_list = await self._fetch_all(
            ctx, self._select_query, _ByNeonTxSig(neon_tx_hash.to_string()), record_type=_RecordWithCost
        )
        return tuple([rec.to_alt_model() for rec in rec_list])

    async def get_alt_sig_list_by_neon_tx_hash(
        self,
        ctx: DbTxCtx,
        neon_tx_hash: EthTxHash,
    ) -> tuple[tuple[int, SolTxSig], ...]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_sig_query,
            _ByNeonTxSig(neon_tx_hash.to_string()),
            record_type=_SolBlockTxSig,
        )
        return tuple([(rec.block_slot, SolTxSig.from_raw(rec.sol_sig)) for rec in rec_list])


@dataclass(frozen=True)
class _Record:
    sol_sig: str
    block_slot: int
    idx: int
    inner_idx: int | None
    is_success: bool
    ix_code: int
    alt_address: str
    neon_sig: str

    @classmethod
    def from_alt_model(cls, sol_alt: SolNeonAltIxModel) -> Self:
        return cls(
            sol_sig=sol_alt.sol_tx_sig.to_string(),
            block_slot=sol_alt.slot,
            idx=sol_alt.sol_ix_idx,
            inner_idx=sol_alt.sol_inner_ix_idx,
            is_success=sol_alt.is_success,
            ix_code=int(sol_alt.alt_ix_code),
            alt_address=sol_alt.alt_address.to_string(),
            neon_sig=sol_alt.neon_tx_hash.to_string(),
        )


@dataclass(frozen=True)
class _RecordWithCost(_Record):
    operator: str
    sol_spent: int

    def to_alt_model(self) -> SolNeonAltIxModel:
        return SolNeonAltIxModel(
            sol_tx_sig=self.sol_sig,
            slot=self.block_slot,
            sol_ix_idx=self.idx,
            sol_inner_ix_idx=self.inner_idx,
            is_success=self.is_success,
            sol_signer=self.operator,
            sol_tx_cost=SolTxCostModel(
                sol_tx_sig=self.sol_sig,
                slot=self.block_slot,
                is_success=self.is_success,
                operator=self.operator,
                sol_spent=self.sol_spent,
            ),
            ix_code=self.ix_code,
            alt_address=self.alt_address,
            neon_tx_hash=self.neon_sig,
        )


@dataclass(frozen=True)
class _SolBlockTxSig:
    block_slot: int
    sol_sig: str


@dataclass(frozen=True)
class _ByNeonTxSig:
    neon_tx_hash: str

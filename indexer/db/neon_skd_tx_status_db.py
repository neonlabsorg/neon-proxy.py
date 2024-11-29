from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx, DbQueryBody, DbSql, DbSqlParam
from common.ethereum.hash import EthTxHash
from common.solana.pubkey import SolPubKey
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxStatusInfo
from ..base.history_skd_db import SkdTxDbTable

_LOG = logging.getLogger(__name__)


class NeonSkdTxStatusDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(
            db, "neon_scheduled_transactions_status", _Record, key_list=("neon_sig", "block_slot", "status")
        )
        self._select_by_tx_hash_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_by_tx_hash_sql = DbSql(
            """;
            SELECT
              {column_list}
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            WHERE
              a.neon_sig = {neon_tx_hash}
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            block_table_name=self._block_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        self._select_by_tx_hash_query = await self._db.sql_to_query(select_by_tx_hash_sql)

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        rec_list = [_Record.from_tx(b, tx) for b in block_list for tx in b.iter_neon_skd_tx_status()]
        await self._insert_row_list(ctx, rec_list)

    async def get_holder_address(self, ctx: DbTxCtx, neon_tx_hash: EthTxHash) -> SolPubKey | None:
        rec_list = await self._fetch_all(
            ctx,
            self._select_by_tx_hash_query,
            _ByNeonTxHash(neon_tx_hash=neon_tx_hash.to_string()),
        )
        for rec in rec_list:
            if not (holder_address := SolPubKey.from_raw(rec.holder_address)).is_empty:
                return holder_address
        return None


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    is_active: bool
    neon_sig: str
    holder_address: str
    status: int

    @classmethod
    def from_tx(cls, block: NeonIndexedBlockInfo, tx: NeonIndexedSkdTxStatusInfo) -> Self:
        return cls(
            neon_sig=tx.neon_tx_hash.to_string(),
            tree_address=tx.tree_address.to_string(),
            is_active=False,
            holder_address=tx.holder_address.to_string(),
            status=tx.status.value,
            block_slot=block.slot,
        )


@dataclass(frozen=True)
class _ByNeonTxHash:
    neon_tx_hash: str

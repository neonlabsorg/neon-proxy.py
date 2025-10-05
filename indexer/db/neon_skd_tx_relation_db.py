from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence, ClassVar, Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonSkdTxStatus
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxRelationInfo, NeonIndexedSkdTxStatusInfo

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NeonSkdTxRelationInfo:
    parent_tx_hash_set: set[EthTxHash]
    child_tx_hash_set: set[EthTxHash]
    #
    _default: ClassVar[NeonSkdTxRelationInfo | None] = None

    @classmethod
    def default(cls) -> NeonSkdTxRelationInfo:
        if cls._default is None:
            cls._default = NeonSkdTxRelationInfo(
                parent_tx_hash_set=set(),
                child_tx_hash_set=set(),
            )

        return cls._default


class NeonSkdTxRelationDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(
            db,
            "neon_scheduled_transactions_relation",
            _Record,
            key_list=("parent_neon_sig", "child_neon_sig", "block_slot", "is_active"),
        )

        self._select_by_tx_hash_query = DbQueryBody()
        self._activate_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_by_tx_hash_sql = DbSql(
            """;
            (
            SELECT
              {column_list}
            FROM
              {table_name} AS a
            INNER JOIN
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            WHERE
              a.parent_neon_sig = ANY({neon_tx_hash})
            ORDER BY
              a.block_slot ASC
            )
            UNION ALL
            (
            SELECT
              {column_list}
            FROM
              {table_name} AS a
            INNER JOIN
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            WHERE
              a.child_neon_sig = ANY({neon_tx_hash})
            ORDER BY
              a.block_slot ASC
            )
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        activate_sql = DbSql(
            """;
            INSERT INTO {table_name}
               (parent_neon_sig, child_neon_sig, tree_address, root_neon_sig, block_slot, is_active) 
            SELECT DISTINCT
               a.parent_neon_sig, a.child_neon_sig, a.tree_address, a.root_neon_sig, {block_slot}, True
            FROM 
               {table_name} AS a
            INNER JOIN
               {block_table_name} AS b
               ON b.block_slot = a.block_slot
               AND b.is_active = True
            WHERE
               a.child_neon_sig = {child_neon_sig}
               AND a.tree_address = {tree_address}
               AND a.is_active = False
            ON CONFLICT
               DO NOTHING
            """
        ).format(
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            block_slot=DbSqlParam("block_slot"),
            child_neon_sig=DbSqlParam("child_neon_sig"),
            tree_address=DbSqlParam("tree_address"),
        )

        (
            self._select_by_tx_hash_query,
            self._activate_query,
        ) = await self._db.sql_to_query(
            select_by_tx_hash_sql,
            activate_sql,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        insert_list = [_Record.from_tx(b.slot, tx) for b in block_list for tx in b.iter_neon_skd_tx_relation()]

        # fmt: off
        task_list = [
            self._insert_row_list(ctx, insert_list)
        ] + [
            self._update_row(ctx, self._activate_query, _Activate.from_status(b.slot, tx))
            for b in block_list
            for tx in b.iter_neon_skd_tx_status()
            if tx.status in (NeonSkdTxStatus.InProgress, NeonSkdTxStatus.Skipped,)
        ]
        # fmt: on

        await asyncio.gather(*task_list)

    async def get_skd_tx_relation_dict(
        self,
        ctx: DbTxCtx,
        neon_tx_hash_list: Sequence[EthTxHash],
    ) -> dict[EthTxHash, NeonSkdTxRelationInfo]:
        tx_hash_list = [h.to_string() for h in neon_tx_hash_list]
        rec_list = await self._fetch_all(ctx, self._select_by_tx_hash_query, _ByTxHash(neon_tx_hash=tx_hash_list))

        skd_tx_dict: dict[EthTxHash, NeonSkdTxRelationInfo] = dict()
        for r in rec_list:
            parent_tx_hash = EthTxHash.from_raw(r.parent_neon_sig)
            child_tx_hash = EthTxHash.from_raw(r.child_neon_sig)

            if parent_tx_hash in neon_tx_hash_list:
                if not (skd_tx := skd_tx_dict.get(parent_tx_hash, None)):
                    skd_tx = NeonSkdTxRelationInfo(set(), set())
                    skd_tx_dict[parent_tx_hash] = skd_tx
                skd_tx.child_tx_hash_set.add(child_tx_hash)

            if child_tx_hash in neon_tx_hash_list:
                if not (skd_tx := skd_tx_dict.get(child_tx_hash, None)):
                    skd_tx = NeonSkdTxRelationInfo(set(), set())
                    skd_tx_dict[child_tx_hash] = skd_tx
                skd_tx.parent_tx_hash_set.add(parent_tx_hash)
        return skd_tx_dict


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    root_neon_sig: str
    parent_neon_sig: str
    child_neon_sig: str
    is_active: bool

    @classmethod
    def from_tx(cls, slot: int, tx: NeonIndexedSkdTxRelationInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            root_neon_sig=tx.root_neon_tx_hash.to_string(),
            is_active=False,
            parent_neon_sig=tx.parent_tx_hash.to_string(),
            child_neon_sig=tx.child_tx_hash.to_string(),
        )


@dataclass(frozen=True)
class _Activate:
    block_slot: int
    tree_address: str
    child_neon_sig: str

    @classmethod
    def from_status(cls, slot: int, tx: NeonIndexedSkdTxStatusInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            child_neon_sig=tx.neon_tx_hash.to_string(),
        )


@dataclass(frozen=True)
class _ByTxHash:
    neon_tx_hash: list[str]

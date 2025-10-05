from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence, Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonSkdTxModel, NeonTxModel
from common.solana.pubkey import SolPubKey
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxInfo

_LOG = logging.getLogger(__name__)


class NeonSkdTxDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_scheduled_transactions", _Record, key_list=("neon_sig", "block_slot"))
        self._select_top_tx_query = DbQueryBody()
        self._select_by_new_slot_query = DbQueryBody()
        self._select_by_old_slot_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        base_hdr_sql = DbSql(
            """;
            SELECT
              {column_list},
              c.sol_sig,
              c.sol_payer,
              c.neon_payer,
              c.nonce,
              c.chain_id,
              d.rlp_body
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            LEFT OUTER JOIN
              {skd_body_table_name} AS d
              ON d.neon_sig = a.neon_sig
            INNER JOIN
              {skd_sig_table_name} AS c
              ON c.tree_address = a.tree_address
              AND c.neon_sig = a.neon_sig
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            block_table_name=self._block_table_name,
            skd_sig_table_name=self._skd_sig_table_name,
            skd_body_table_name=self._skd_body_table_name,
        )

        select_by_new_slot_sql = base_hdr_sql
        select_by_new_slot_sql += DbSql(
            """
              AND c.is_active = False
            WHERE
              a.block_slot > {slot}
              AND a.index = 0
              AND d.neon_sig IS NOT NULL
            ORDER BY
              a.block_slot DESC
            LIMIT
              {limit}
            """
        ).format(
            slot=DbSqlParam("slot"),
            limit=DbSqlParam("limit"),
        )

        select_by_old_slot_sql = base_hdr_sql
        select_by_old_slot_sql += DbSql(
            """
            WHERE
              a.block_slot <= {slot}
              AND a.index = 0
            ORDER BY
              a.block_slot ASC
            LIMIT
              {limit}
            """
        ).format(
            slot=DbSqlParam("slot"),
            limit=DbSqlParam("limit"),
        )

        select_top_tx_sql = base_hdr_sql
        select_top_tx_sql += DbSql(
            """
            WHERE 
              a.tree_address = {tree_address}
              AND a.root_neon_sig = {root_neon_sig}
              AND a.index = 0
            """
        ).format(
            tree_address=DbSqlParam("tree_address"),
            root_neon_sig=DbSqlParam("root_neon_sig"),
        )

        (
            self._select_top_tx_query,
            self._select_by_new_slot_query,
            self._select_by_old_slot_query,
        ) = await self._db.sql_to_query(
            select_top_tx_sql,
            select_by_new_slot_sql,
            select_by_old_slot_sql,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        # fmt: off
        rec_list = [
            _Record.from_tx(b.slot, tx)
            for b in block_list
            for tx in b.iter_neon_skd_tx()
            if not tx.index  # only top txs
        ]
        # fmt: on
        await self._insert_row_list(ctx, rec_list)

    async def get_tx_list(self, ctx: DbTxCtx, slot: int, limit: int) -> Sequence[NeonSkdTxModel]:
        rec_list = await self._fetch_all(
            ctx,
            self._select_by_new_slot_query,
            _BySlot(slot=slot, limit=limit),
            record_type=_RecordWithPayer,
        )
        return tuple([rec.to_neon_skd_tx() for rec in rec_list if rec])

    async def get_old_tx_list_by_slot(self, ctx: DbTxCtx, min_slot: int, limit: int) -> Sequence[NeonSkdTxModel]:
        by_slot = _BySlot(slot=min_slot, limit=limit)
        rec_list = await self._fetch_all(
            ctx,
            self._select_by_old_slot_query,
            by_slot,
            record_type=_RecordWithPayer,
        )
        return tuple([rec.to_neon_skd_tx() for rec in rec_list if rec])

    async def get_top_tx(self, ctx: DbTxCtx, tree_address: SolPubKey, root_neon_tx_hash: EthTxHash) -> NeonSkdTxModel:
        rec = await self._fetch_one(
            ctx,
            self._select_top_tx_query,
            _ByTreeAddrAndTxHash(
                tree_address=tree_address.to_string(),
                root_neon_sig=root_neon_tx_hash.to_string(),
            ),
            record_type=_RecordWithPayer,
        )
        return rec.to_neon_skd_tx() if rec else None

    async def commit_tx(
        self,
        ctx: DbTxCtx,
        slot: int,
        tree_address: SolPubKey,
        root_neon_tx_hash: EthTxHash,
        neon_tx: NeonTxModel,
    ) -> None:
        rec = _Record.from_neon_tx(slot, tree_address, root_neon_tx_hash, neon_tx)
        await self._insert_row(ctx, rec)


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    root_neon_sig: str
    is_active: bool
    neon_sig: str
    index: int

    @classmethod
    def from_tx(cls, slot: int, tx: NeonIndexedSkdTxInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            root_neon_sig=tx.root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            index=tx.index,
        )

    @classmethod
    def from_neon_tx(cls, slot: int, tree_address: SolPubKey, root_neon_tx_hash: EthTxHash, tx: NeonTxModel) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tree_address.to_string(),
            root_neon_sig=root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            index=tx.index,
        )


@dataclass(frozen=True)
class _RecordWithPayer(_Record):
    sol_sig: str
    sol_payer: str
    neon_payer: str
    nonce: int
    chain_id: int
    rlp_body: bytes

    def to_neon_skd_tx(self) -> NeonSkdTxModel:
        return NeonSkdTxModel(
            slot=self.block_slot,
            neon_tx_hash=self.neon_sig,
            sol_skd_tx_sig=self.sol_sig,
            sol_skd_payer=self.sol_payer,
            neon_payer=self.neon_payer,
            chain_id=self.chain_id,
            nonce=self.nonce,
            rlp_tx=self.rlp_body,
            tree_address=self.tree_address,
        )


@dataclass(frozen=True)
class _BySlot:
    slot: int
    limit: int


@dataclass(frozen=True)
class _ByTreeAddrAndTxHash:
    tree_address: str
    root_neon_sig: str

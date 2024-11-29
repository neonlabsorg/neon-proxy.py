from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonSkdTxModel, NeonTxModel
from common.solana.pubkey import SolPubKey
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


class NeonSkdTxDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_scheduled_transactions", _Record, key_list=("neon_sig", "block_slot"))
        self._select_by_tx_hash_query = DbQueryBody()
        self._select_by_new_slot_query = DbQueryBody()
        self._select_by_old_slot_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_by_new_slot_sql = DbSql(
            """;
            SELECT
              {column_list},
              c.sol_sig,
              c.sol_payer,
              c.neon_payer,
              c.chain_id
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            INNER JOIN
              {skd_sig_table_name} AS c
              ON c.tree_address = a.tree_address
              AND c.neon_sig = a.neon_sig
              AND c.is_active = False
            WHERE
              a.block_slot >= {slot}
              AND a.index = 0
              AND a.has_rlp_body = True
            ORDER BY
              a.block_slot ASC
            LIMIT 
              {limit}
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            block_table_name=self._block_table_name,
            skd_sig_table_name=self._skd_sig_table_name,
            slot=DbSqlParam("slot"),
            limit=DbSqlParam("limit"),
        )

        select_by_old_slot_sql = DbSql(
            """;
            SELECT
              {column_list},
              c.sol_sig,
              c.sol_payer,
              c.neon_payer,
              c.chain_id
            FROM
              {table_name} AS a
            INNER JOIN
              {skd_sig_table_name} AS c
              ON c.tree_address = a.tree_address
              AND c.neon_sig = a.neon_sig
            WHERE
              a.index = 0
              AND a.block_slot <= {slot}
            ORDER BY
              a.block_slot DESC
            LIMIT
              {limit}
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            skd_sig_table_name=self._skd_sig_table_name,
            slot=DbSqlParam("slot"),
            limit=DbSqlParam("limit"),
        )

        select_by_tx_hash_sql = DbSql(
            """;
            SELECT 
              {column_list},
              c.sol_sig,
              c.sol_payer,
              c.neon_payer,
              c.chain_id
            FROM 
              {table_name} AS a
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            INNER JOIN
              {skd_sig_table_name} AS c
              ON c.tree_address = a.tree_address
              AND c.neon_sig = a.neon_sig
              AND c.is_active = False
            WHERE 
              a.neon_sig = {neon_tx_hash}
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            skd_sig_table_name=self._skd_sig_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        (
            self._select_by_tx_hash_query,
            self._select_by_new_slot_query,
            self._select_by_old_slot_query,
        ) = await self._db.sql_to_query(
            select_by_tx_hash_sql,
            select_by_new_slot_sql,
            select_by_old_slot_sql,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        # fmt: off
        rec_list = [
            _Record.from_tx(b.slot, tx.tree_address, tx)
            for b in block_list
            for tx in b.iter_neon_skd_tx()
            if tx.rlp_tx or (tx.index == 0)
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

    async def get_tx_by_hash(self, ctx: DbTxCtx, neon_tx_hash: EthTxHash) -> NeonSkdTxModel | None:
        rec = await self._fetch_one(
            ctx,
            self._select_by_tx_hash_query,
            _ByNeonTxHash(neon_tx_hash=neon_tx_hash.to_string()),
            record_type=_RecordWithPayer,
        )
        return rec.to_neon_skd_tx() if rec else None

    async def commit_tx(self, ctx: DbTxCtx, slot: int, tree_address: SolPubKey, neon_tx: NeonTxModel) -> None:
        rec = _Record.from_tx(slot, tree_address, neon_tx)
        await self._insert_row(ctx, rec)


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    is_active: bool
    neon_sig: str
    nonce: int
    index: int
    rlp_body: bytes
    has_rlp_body: bool

    @classmethod
    def from_tx(cls, slot: int, tree_address: SolPubKey, tx: NeonSkdTxModel | NeonTxModel) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tree_address.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            nonce=tx.nonce,
            index=tx.index,
            rlp_body=tx.rlp_tx.to_bytes(),
            has_rlp_body=(len(tx.rlp_tx) > 0),
        )


@dataclass(frozen=True)
class _RecordWithPayer(_Record):
    sol_sig: str
    sol_payer: str
    neon_payer: str
    chain_id: int

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
            index=self.index,
            tree_address=self.tree_address,
        )


@dataclass(frozen=True)
class _BySlot:
    slot: int
    limit: int


@dataclass(frozen=True)
class _ByNeonTxHash:
    neon_tx_hash: str

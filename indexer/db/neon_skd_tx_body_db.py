from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence, Self

from common.db.db_connect import DbConnection, DbTxCtx, DbQueryBody, DbSqlParam, DbSql
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonTxModel, NeonSkdTxModel
from common.solana.pubkey import SolPubKey
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxInfo

_LOG = logging.getLogger(__name__)


class NeonSkdTxBodyDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_scheduled_transactions_body", _Record, key_list=("neon_sig",))
        self._select_by_tx_hash_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_by_tx_hash_sql = DbSql(
            """;
            SELECT
              b.block_slot,
              c.tree_address,
              c.neon_sig,
              c.sol_sig,
              c.sol_payer,
              c.neon_payer,
              c.nonce,
              c.chain_id,
              a.rlp_body
            FROM 
              {skd_sig_table_name} AS c
            INNER JOIN 
              {block_table_name} AS b
              ON b.block_slot = c.block_slot
              AND b.is_active = True
            LEFT OUTER JOIN
              {table_name} AS a
              ON a.tree_address = c.tree_address
              AND a.neon_sig = c.neon_sig
            WHERE 
              c.neon_sig = {neon_tx_hash}
            """
        ).format(
            block_table_name=self._block_table_name,
            skd_sig_table_name=self._skd_sig_table_name,
            table_name=self._table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        self._select_by_tx_hash_query = await self._db.sql_to_query(select_by_tx_hash_sql)

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        # fmt: off
        rec_list = [
            _Record.from_tx(b.slot, tx)
            for b in block_list
            for tx in b.iter_neon_skd_tx()
            if tx.rlp_tx
        ]
        # fmt: on
        await self._insert_row_list(ctx, rec_list)

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

    async def get_tx_by_hash(self, ctx: DbTxCtx, neon_tx_hash: EthTxHash) -> NeonSkdTxModel | None:
        rec = await self._fetch_one(
            ctx,
            self._select_by_tx_hash_query,
            _ByTxHash(neon_tx_hash=neon_tx_hash.to_string()),
            record_type=_RecordBody,
        )
        return rec.to_neon_skd_tx() if rec else None


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    root_neon_sig: str
    is_active: bool
    neon_sig: str
    rlp_body: bytes

    @classmethod
    def from_tx(cls, slot: int, tx: NeonIndexedSkdTxInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            root_neon_sig=tx.root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            rlp_body=tx.rlp_tx,
        )

    @classmethod
    def from_neon_tx(cls, slot: int, tree_address: SolPubKey, root_neon_tx_hash: EthTxHash, neon_tx: NeonTxModel) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tree_address.to_string(),
            root_neon_sig=root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=neon_tx.neon_tx_hash.to_string(),
            rlp_body=neon_tx.rlp_tx.to_bytes(),
        )


@dataclass(frozen=True)
class _RecordBody:
    block_slot: int
    neon_sig: str
    sol_sig: str
    sol_payer: str
    neon_payer: str
    chain_id: str
    nonce: str
    rlp_body: str
    tree_address: str

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
class _ByTxHash:
    neon_tx_hash: str

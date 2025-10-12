from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence, ClassVar, Self

from common.db.db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonSkdTxStatus, NeonTxModel
from common.solana.pubkey import SolPubKey
from common.solana.signature import SolTxSig
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxStatusInfo, NeonIndexedSkdTxInfo

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NeonSkdTxSigInfo:
    neon_tx_hash: EthTxHash
    # Solana:
    sol_sig: SolTxSig
    sol_payer: SolPubKey
    # small optimization
    _default: ClassVar[NeonSkdTxSigInfo | None] = None

    @classmethod
    def default(cls) -> NeonSkdTxSigInfo:
        if not cls._default:
            cls._default = NeonSkdTxSigInfo(
                neon_tx_hash=EthTxHash.default(),
                sol_sig=SolTxSig.default(),
                sol_payer=SolPubKey.default(),
            )
        return cls._default


class NeonSkdTxSigDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(
            db,
            "neon_scheduled_transactions_signature",
            _Record,
            key_list=("neon_sig", "block_slot", "is_active"),
        )

        self._select_by_tx_hash_query = DbQueryBody()
        self._select_tx_hash_list_by_root_tx_hash_query = DbQueryBody()
        self._activate_query = DbQueryBody()

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
              a.neon_sig = ANY({neon_tx_hash})
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            neon_tx_hash=DbSqlParam("neon_tx_hash"),
        )

        activate_sql = DbSql(
            """;
            INSERT INTO {table_name} (
                sol_sig, sol_payer, neon_payer, 
                nonce, chain_id, 
                tree_address, root_neon_sig, neon_sig, 
                block_slot, is_active
            ) 
            SELECT DISTINCT
               a.sol_sig, a.sol_payer, a.neon_payer, 
               a.nonce, a.chain_id, 
               a.tree_address, a.root_neon_sig, 
               a.neon_sig, 
               {block_slot}, True
            FROM 
               {table_name} AS a
            INNER JOIN
               {block_table_name} AS b
               ON b.block_slot = a.block_slot
               AND b.is_active = True
            WHERE
               a.neon_sig = {neon_sig}
               AND a.tree_address = {tree_address}
               AND a.is_active = False
            ON CONFLICT
               DO NOTHING
            """
        ).format(
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            block_slot=DbSqlParam("block_slot"),
            tree_address=DbSqlParam("tree_address"),
            neon_sig=DbSqlParam("neon_sig"),
        )

        select_tx_hash_list_by_root_tx_hash_sql = DbSql(
            """;
            SELECT DISTINCT
              a.neon_sig
            FROM
              {table_name} AS a
            INNER JOIN
              {block_table_name} AS b
              ON b.block_slot = a.block_slot
              AND b.is_active = True
            WHERE
              a.root_neon_sig = {root_neon_tx_hash}
            """
        ).format(
            table_name=self._table_name,
            block_table_name=self._block_table_name,
            root_neon_tx_hash=DbSqlParam("root_neon_tx_hash"),
        )

        (
            self._select_by_tx_hash_query,
            self._select_tx_hash_list_by_root_tx_hash_query,
            self._activate_query,
        ) = await self._db.sql_to_query(
            select_by_tx_hash_sql,
            select_tx_hash_list_by_root_tx_hash_sql,
            activate_sql,
        )

    async def set_block_list(self, ctx: DbTxCtx, block_list: Sequence[NeonIndexedBlockInfo]) -> None:
        insert_list = [_Record.from_tx(b.slot, tx) for b in block_list for tx in b.iter_neon_skd_tx()]

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

    async def get_skd_tx_sig_dict(
        self,
        ctx: DbTxCtx,
        neon_tx_hash_list: Sequence[EthTxHash],
    ) -> dict[EthTxHash, NeonSkdTxSigInfo]:
        tx_hash_list = [h.to_string() for h in neon_tx_hash_list]
        rec_list = await self._fetch_all(ctx, self._select_by_tx_hash_query, _ByTxHash(neon_tx_hash=tx_hash_list))
        skd_tx_list = tuple([r.to_clean_copy() for r in rec_list if r])
        return {m.neon_tx_hash: m for m in skd_tx_list}

    async def get_neon_skd_tx_hash_list_by_root_hash(
        self,
        ctx: DbTxCtx,
        root_neon_tx_hash: EthTxHash,
    ) -> Sequence[EthTxHash]:
        root_tx_hash = root_neon_tx_hash.to_string()
        rec_list: list[_RecordSig] = await self._fetch_all(
            ctx,
            self._select_tx_hash_list_by_root_tx_hash_query,
            _ByRootTxHash(root_neon_tx_hash=root_tx_hash),
            record_type=_RecordSig,
        )
        tx_hash_list = [r.neon_tx_hash for r in rec_list if r != root_tx_hash]
        return tuple([root_tx_hash] + tx_hash_list)


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    root_neon_sig: str
    neon_sig: str
    sol_sig: str
    sol_payer: str
    neon_payer: str
    nonce: int
    chain_id: int
    is_active: bool

    @classmethod
    def from_tx(cls, slot: int, tx: NeonIndexedSkdTxInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            root_neon_sig=tx.root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            sol_sig=tx.sol_skd_tx_sig.to_string(),
            sol_payer=tx.sol_skd_payer.to_string(),
            neon_payer=tx.neon_payer.to_string(),
            nonce=tx.nonce,
            chain_id=tx.chain_id,
        )

    @classmethod
    def from_neon_tx(cls, slot: int, tree_address: SolPubKey, root_neon_tx_hash: EthTxHash, tx: NeonTxModel) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tree_address.to_string(),
            root_neon_sig=root_neon_tx_hash.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            sol_sig=tx.sol_skd_tx_sig.to_string(),
            sol_payer=tx.sol_skd_payer.to_string(),
            neon_payer=tx.payer.to_string(),
            nonce=tx.nonce,
            chain_id=tx.chain_id,
        )

    def to_clean_copy(self) -> NeonSkdTxSigInfo:
        return NeonSkdTxSigInfo(
            neon_tx_hash=EthTxHash.from_raw(self.neon_sig),
            sol_sig=SolTxSig.from_raw(self.sol_sig),
            sol_payer=SolPubKey.from_raw(self.sol_payer),
        )


@dataclass(frozen=True)
class _Activate:
    block_slot: int
    neon_sig: str
    tree_address: str

    @classmethod
    def from_status(cls, slot: int, tx: NeonIndexedSkdTxStatusInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            neon_sig=tx.neon_tx_hash.to_string(),
        )


@dataclass(frozen=True)
class _RecordSig:
    neon_sig: str

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return EthTxHash.from_raw(self.neon_sig)


@dataclass(frozen=True)
class _ByTxHash:
    neon_tx_hash: list[str]


@dataclass(frozen=True)
class _ByRootTxHash:
    root_neon_tx_hash: str

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx
from common.neon.transaction_model import NeonTxModel
from common.solana.pubkey import SolPubKey
from ..base.history_skd_db import SkdTxDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedSkdTxInfo

_LOG = logging.getLogger(__name__)


class NeonSkdTxBodyDb(SkdTxDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "neon_scheduled_transactions_body", _Record, key_list=("neon_sig",))

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

    async def commit_tx(self, ctx: DbTxCtx, slot: int, tree_address: SolPubKey, neon_tx: NeonTxModel) -> None:
        rec = _Record.from_neon_tx(slot, tree_address, neon_tx)
        await self._insert_row(ctx, rec)


@dataclass(frozen=True)
class _Record:
    block_slot: int
    tree_address: str
    is_active: bool
    neon_sig: str
    rlp_body: bytes

    @classmethod
    def from_tx(cls, slot: int, tx: NeonIndexedSkdTxInfo) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tx.tree_address.to_string(),
            is_active=False,
            neon_sig=tx.neon_tx_hash.to_string(),
            rlp_body=tx.rlp_tx,
        )

    @classmethod
    def from_neon_tx(cls, slot: int, tree_address: SolPubKey, neon_tx: NeonTxModel) -> Self:
        return cls(
            block_slot=slot,
            tree_address=tree_address.to_string(),
            is_active=False,
            neon_sig=neon_tx.neon_tx_hash.to_string(),
            rlp_body=neon_tx.rlp_tx.to_bytes(),
        )

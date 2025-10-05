from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence

from common.db.db_connect import DbTxCtx, DbSqlIdent, DbQueryBody, DbSql, DbSqlParam
from common.ethereum.hash import EthTxHash
from common.solana.pubkey import SolPubKey
from .objects import NeonIndexedDoneSkdTxInfo
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


class SkdTxDbTable(HistoryDbTable):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._skd_sig_table_name = DbSqlIdent("neon_scheduled_transactions_signature")
        self._skd_body_table_name = DbSqlIdent("neon_scheduled_transactions_body")

        self._delete_by_tree_addr_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        # because the tx-hash is a unique value, and it is impossible to predefine it
        #   as a result, it is impossible to store the same tx-hash in two different tree,
        #   we can delete records just by root-tx-hash w/o checking the tree-address
        delete_by_tree_addr_sql = DbSql(
            """;
            DELETE FROM
               {table_name}
            WHERE
                root_neon_sig = ANY({root_neon_sig_list}) AND
                block_slot < {finalized_slot} AND
                is_active = False
            """
        ).format(
            table_name=self._table_name,
            finalized_slot=DbSqlParam("finalized_slot"),
            root_neon_sig_list=DbSqlParam("root_neon_sig_list"),
        )

        self._delete_by_tree_addr_query = await self._db.sql_to_query(delete_by_tree_addr_sql)

    async def finalize_block_list(
        self,
        ctx: DbTxCtx,
        from_slot: int,
        to_slot: int,
        block_list: Sequence[NeonIndexedBlockInfo],
        slot_list: Sequence[int],
    ) -> None:
        await super().finalize_block_list(ctx, from_slot, to_slot, block_list, slot_list)

        # fmt: off
        await asyncio.gather(*[
            self._destroy_tree_account(ctx, block.slot, list(block.iter_done_neon_skd_tree()))
            for block in block_list
        ])
        # fmt: on

    async def destroy_tree_account(
        self,
        ctx: DbTxCtx,
        finalized_slot: int,
        tree_address: SolPubKey,
        root_neon_tx_hash: EthTxHash,
    ) -> None:
        await self._destroy_tree_account(
            ctx,
            finalized_slot,
            tuple([NeonIndexedDoneSkdTxInfo(tree_address, root_neon_tx_hash)]),
        )

    async def _destroy_tree_account(
        self,
        ctx: DbTxCtx,
        finalized_slot: int,
        tree_list: Sequence[NeonIndexedDoneSkdTxInfo],
    ) -> None:
        if not tree_list:
            return

        tx_hash_list = [tx.root_neon_tx_hash.to_string() for tx in tree_list]
        await self._update_row(
            ctx,
            self._delete_by_tree_addr_query,
            _ByRootTxHashAndSlot(root_neon_sig_list=tx_hash_list, finalized_slot=finalized_slot),
        )


@dataclass(frozen=True)
class _ByRootTxHashAndSlot:
    root_neon_sig_list: list[str]
    finalized_slot: int

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from common.db.db_connect import DbTxCtx, DbSql, DbSqlParam, DbQueryBody, DbSqlIdent
from common.solana.pubkey import SolPubKey
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

        delete_by_tree_addr_sql = DbSql(
            """;
            DELETE FROM
               {table_name}
            WHERE
                tree_address = ANY({tree_address_list}) AND
                is_active = False
            """
        ).format(
            table_name=self._table_name,
            tree_address_list=DbSqlParam("tree_address_list"),
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

        tree_addr_list = [addr.to_string() for block in block_list for addr in block.iter_done_neon_skd_tree()]
        await self.destroy_tree_list(ctx, tree_addr_list)

    async def destroy_tree_list(self, ctx: DbTxCtx, tree_address_list: Sequence[str | SolPubKey]) -> None:
        if not tree_address_list:
            return

        if isinstance(tree_address_list, str):
            tree_address_list = [tree_address_list]
        elif isinstance(tree_address_list, SolPubKey):
            tree_address_list = [tree_address_list.to_string()]
        elif isinstance(tree_address_list[0], SolPubKey):
            tree_address_list = [a.to_string() for a in tree_address_list]

        await self._update_row(ctx, self._delete_by_tree_addr_query, _ByTreeAddr(tree_address_list=tree_address_list))

@dataclass(frozen=True)
class _ByTreeAddr:
    tree_address_list: list[str]

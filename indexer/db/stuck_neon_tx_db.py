from __future__ import annotations

from common.db.db_connect import DbConnection, DbTxCtx
from ..base.objects import NeonIndexedBlockInfo
from ..base.stuck_db import StuckDBTable


class StuckNeonTxDb(StuckDBTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "stuck_neon_transactions", has_finalized=True)

    async def set_obj_list(self, ctx: DbTxCtx, neon_block: NeonIndexedBlockInfo) -> None:
        neon_tx_list = tuple([tx.to_dict() for tx in neon_block.iter_stuck_neon_tx()])
        await self._set_obj_list(ctx, neon_block, neon_tx_list)

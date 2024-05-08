from __future__ import annotations

from common.db.db_connect import DbConnection, DbTxCtx
from ..base.objects import NeonIndexedBlockInfo
from ..base.stuck_db import StuckDBTable


class StuckNeonHolderDb(StuckDBTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "stuck_neon_holders")

    async def set_obj_list(self, ctx: DbTxCtx, neon_block: NeonIndexedBlockInfo) -> None:
        neon_holder_list = tuple([holder.to_dict() for holder in neon_block.iter_stuck_neon_holder()])
        await self._set_obj_list(ctx, neon_block, neon_holder_list)

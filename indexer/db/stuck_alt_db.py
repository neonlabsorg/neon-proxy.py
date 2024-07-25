from __future__ import annotations

from common.db.db_connect import DbConnection, DbTxCtx
from ..base.stuck_db import StuckDBTable
from ..base.objects import NeonIndexedBlockInfo


class StuckNeonAltDb(StuckDBTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "solana_alt_infos")

    async def set_obj_list(self, ctx: DbTxCtx, neon_block: NeonIndexedBlockInfo) -> None:
        alt_list = tuple([alt.to_dict() for alt in neon_block.iter_alt()])
        await self._set_obj_list(ctx, neon_block, alt_list)

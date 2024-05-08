from __future__ import annotations

import asyncio
import logging
from typing import Final

from typing_extensions import Self

from common.config.config import Config
from common.db.constant_db import ConstantDb
from common.db.db_connect import DbConnection, DbTxCtx
from .gas_less_usage_db import GasLessUsageDb
from .neon_tx_db import NeonTxDb
from .neon_tx_log_db import NeonTxLogDb
from .solana_alt_tx_db import SolAltTxDb
from .solana_block_db import SolBlockDb
from .solana_neon_tx_db import SolNeonTxDb
from .solana_tx_cost_db import SolTxCostDb
from .stuck_alt_db import StuckNeonAltDb
from .stuck_neon_holder_db import StuckNeonHolderDb
from .stuck_neon_tx_db import StuckNeonTxDb
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


class IndexerDb:
    _max_u64: Final[int] = 2**64 - 1
    base_start_slot_name: Final[str] = "starting_slot"
    base_min_used_slot_name: Final[str] = "min_receipt_slot"
    finalized_slot_name: Final[str] = "finalized_slot"
    latest_slot_name: Final[str] = "latest_slot"

    def __init__(self, cfg: Config, db_conn: DbConnection, reindex_ident: str):
        self._cfg = cfg
        self._db_conn = db_conn

        self._reindex_ident = reindex_ident
        if self.is_reindexing_mode:
            reindex_ident += ":"

        self._start_slot_name = reindex_ident + self.base_start_slot_name
        self._stop_slot_name = reindex_ident + "stop_slot"
        self._min_used_slot_name = reindex_ident + self.base_min_used_slot_name

        self._constant_db = ConstantDb(db_conn)
        self._sol_block_db = SolBlockDb(db_conn)
        self._sol_tx_cost_db = SolTxCostDb(db_conn)
        self._neon_tx_db = NeonTxDb(db_conn)
        self._sol_neon_tx_db = SolNeonTxDb(db_conn)
        self._neon_tx_log_db = NeonTxLogDb(db_conn)
        self._sol_alt_tx_db = SolAltTxDb(db_conn)
        self._gas_less_usage_db = GasLessUsageDb(db_conn)
        self._stuck_neon_holder_db = StuckNeonHolderDb(db_conn)
        self._stuck_neon_tx_db = StuckNeonTxDb(db_conn)
        self._stuck_neon_alt_db = StuckNeonAltDb(db_conn)

        self._db_list = (
            self._constant_db,
            self._sol_block_db,
            self._sol_tx_cost_db,
            self._neon_tx_db,
            self._sol_neon_tx_db,
            self._neon_tx_log_db,
            self._sol_alt_tx_db,
            self._gas_less_usage_db,
            self._stuck_neon_holder_db,
            self._stuck_neon_tx_db,
            self._stuck_neon_alt_db,
        )

        self._history_db_list = (
            self._sol_tx_cost_db,
            self._neon_tx_db,
            self._sol_neon_tx_db,
            self._neon_tx_log_db,
            self._sol_alt_tx_db,
            self._gas_less_usage_db,
        )

        self._stuck_db_list = (
            self._stuck_neon_holder_db,
            self._stuck_neon_tx_db,
            self._stuck_neon_alt_db,
        )

        self._start_slot = 0
        self._stop_slot = self._max_u64
        self._min_used_slot = 0
        self._latest_slot = 0
        self._finalized_slot = 0

    @classmethod
    async def from_db_conn(cls, cfg: Config, db: DbConnection, *, reindex_ident: str = "") -> Self:
        self = cls(cfg, db, reindex_ident)
        await self.start()

        self._min_used_slot = await self._constant_db.get_int(None, self._min_used_slot_name, 0)
        self._start_slot = await self._constant_db.get_int(None, self._start_slot_name, self._min_used_slot)
        self._stop_slot = await self._constant_db.get_int(None, self._stop_slot_name, self._max_u64)

        return self

    @classmethod
    async def from_slot_range(
        cls, cfg: Config, db: DbConnection, start_slot: int, *, reindex_ident: str = "", stop_slot: int = None
    ) -> Self:
        self = cls(cfg, db, reindex_ident)
        await self.start()

        self._start_slot = start_slot
        self._min_used_slot = start_slot
        self._stop_slot = stop_slot or self._max_u64

        task_list = list()
        task_list.append(self._constant_db.set(None, self._min_used_slot_name, start_slot))

        if self.is_reindexing_mode:
            task_list.append(self._constant_db.set(None, self._start_slot_name, start_slot))
            task_list.append(self._constant_db.set(None, self._stop_slot_name, stop_slot))

        if await self._constant_db.get_int(None, self.base_start_slot_name, self._max_u64) > start_slot:
            task_list.append(self._constant_db.set(None, self.base_start_slot_name, start_slot))

        await asyncio.gather(*task_list)
        return self

    async def start(self) -> None:
        await asyncio.gather(*[db.start() for db in self._db_list])
        if not self.is_reindexing_mode:
            self._latest_slot = await self.get_latest_slot()
            self._finalized_slot = await self.get_finalized_slot()

    @property
    def reindex_ident(self) -> str:
        return self._reindex_ident

    @property
    def start_slot(self) -> int:
        return self._start_slot

    @property
    def stop_slot(self) -> int:
        return self._stop_slot

    @property
    def is_reindexing_mode(self) -> bool:
        return len(self._reindex_ident) > 0

    async def drop_not_finalized_history(self) -> None:
        async def _tx(ctx: DbTxCtx) -> None:
            await self._finalize_slot_list(ctx, self._latest_slot + 1, (self._finalized_slot,))

        await self._db_conn.run_tx(_tx)

    async def submit_block_list(self, min_used_slot: int, neon_block_queue: tuple[NeonIndexedBlockInfo, ...]) -> None:
        async def _tx(ctx: DbTxCtx) -> None:
            await self._submit_new_block_list(ctx, neon_block_queue)
            if self.is_reindexing_mode:
                return

            last_block = neon_block_queue[-1]
            if last_block.is_finalized:
                await self._finalize_block_list(ctx, last_block, neon_block_queue)
                await self._set_finalized_slot(ctx, last_block.slot)
            else:
                await self._activate_block_list(ctx, last_block, neon_block_queue)

            # doesn't look critical to modify the local cache variables on the last step of the db-tx
            #  if something bad happens, it is already happened
            await self._set_min_used_slot(ctx, min_used_slot)
            await self._set_latest_slot(ctx, last_block.slot)

        await self._db_conn.run_tx(_tx)
        for block in neon_block_queue:
            block.mark_done()

    async def _submit_new_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        new_block_list = tuple([block for block in block_list if not block.is_done])
        if not new_block_list:
            return

        # it doesn't matter in which order the objects will be inserted
        #  they will be available only after activating the block's branch and the latest/finalized blocks
        await asyncio.gather(*[db.set_block_list(None, new_block_list) for db in self._history_db_list])

        # from this point the db-tx starts...
        await self._sol_block_db.set_block_list(ctx, new_block_list)

    async def _finalize_block_list(
        self, ctx: DbTxCtx, last_block: NeonIndexedBlockInfo, block_queue: tuple[NeonIndexedBlockInfo, ...]
    ) -> None:
        for db in self._stuck_db_list:
            await db.set_obj_list(ctx, last_block)

        slot_list = tuple([b.slot for b in block_queue if b.is_done and (b.slot > self._finalized_slot)])
        if slot_list:
            await self._finalize_slot_list(ctx, last_block.slot, slot_list)

    async def _finalize_slot_list(self, ctx, last_slot: int, slot_list: tuple[int, ...]) -> None:
        block_range = self._finalized_slot, last_slot, slot_list
        for db_table in self._history_db_list:
            # it doesn't matter in which order will be removed old records from secondary tables,
            #   so do it on the independent db connections
            await db_table.finalize_block_list(None, *block_range)
        # the branch switching should be atomic
        await self._sol_block_db.finalize_block_list(ctx, *block_range)

    async def _activate_block_list(
        self, ctx: DbTxCtx, last_block: NeonIndexedBlockInfo, block_queue: tuple[NeonIndexedBlockInfo, ...]
    ) -> None:
        if not last_block.is_done:
            await self._stuck_neon_tx_db.set_obj_list(ctx, last_block)

        slot_list = tuple([b.slot for b in block_queue if not b.is_finalized])
        if slot_list:
            await self._sol_block_db.activate_block_list(ctx, self._finalized_slot, slot_list)

    async def _set_finalized_slot(self, ctx: DbTxCtx, slot: int) -> None:
        if self._finalized_slot < slot:
            await self._constant_db.set(ctx, self.finalized_slot_name, slot)
            self._finalized_slot = slot

    async def _set_latest_slot(self, ctx: DbTxCtx, slot: int) -> None:
        if self._latest_slot < slot:
            await self._constant_db.set(ctx, self.latest_slot_name, slot)
            self._latest_slot = slot

    async def _set_min_used_slot(self, ctx: DbTxCtx, slot: int) -> None:
        if self._min_used_slot < slot:
            await self._constant_db.set(ctx, self._min_used_slot_name, slot)
            self._min_used_slot = slot

    async def set_start_slot(self, slot: int) -> None:
        if self._start_slot >= slot:
            return

        await self._set_min_used_slot(None, slot)

        self._start_slot = slot
        if self.is_reindexing_mode:
            await self._constant_db.set(None, self._start_slot_name, slot)

    async def set_stop_slot(self, slot: int) -> None:
        assert self.is_reindexing_mode
        if self._stop_slot < slot:
            self._stop_slot = slot
            await self._constant_db.set(None, self._stop_slot_name, slot)

    async def done(self) -> None:
        await self._constant_db.delete_list(
            None, [self._start_slot_name, self._stop_slot_name, self._min_used_slot_name]
        )

    async def get_earliest_slot(self) -> int:
        return await self._constant_db.get_int(None, self._start_slot_name, 0)

    async def get_latest_slot(self) -> int:
        return await self._constant_db.get_int(None, self.latest_slot_name, 0)

    async def get_finalized_slot(self) -> int:
        return await self._constant_db.get_int(None, self.finalized_slot_name, 0)

    def get_min_used_slot(self) -> int:
        return self._min_used_slot

    async def get_stuck_neon_holder_list(self) -> tuple[int | None, tuple[dict, ...]]:
        return await self._stuck_neon_holder_db.get_obj_list(None, True)

    async def get_stuck_neon_tx_list(self) -> tuple[int | None, tuple[dict, ...]]:
        return await self._stuck_neon_tx_db.get_obj_list(None, True)

    async def get_stuck_neon_alt_list(self) -> tuple[int | None, tuple[dict, ...]]:
        return await self._stuck_neon_alt_db.get_obj_list(None, True)

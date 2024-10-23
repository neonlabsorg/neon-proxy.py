from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .client import SolClient
from ..solana.commit_level import SolCommit
from ..utils.cached import cached_method, cached_property

_LOG = logging.getLogger(__name__)


class SolNotEmptyBlockFinder:
    def __init__(self, sol_client: SolClient, *, start_slot: int | None = None, stop_slot: int | None = None):
        self._sol_client = sol_client
        self._def_start_slot = start_slot
        self._def_stop_slot = stop_slot

    async def find_slot(self) -> int:
        start_slot, stop_slot = await asyncio.gather(self._get_start_slot(), self._get_stop_slot())
        ctx = _Ctx(start_slot, stop_slot)

        if start_slot >= stop_slot:
            _LOG.warning(
                "%s, the start slot %s is bigger or equal to the stop slot, FORCE to use stop slot %s",
                ctx.caption,
                start_slot,
                stop_slot,
            )
            if not await self._has_block(ctx, stop_slot):
                _LOG.debug(
                    "%s, no block at the stop slot %s, move to the start slot %s", ctx.caption, stop_slot, start_slot
                )
                return start_slot
            return stop_slot or 0

        slot = await self._find_slot(_Ctx(start_slot, stop_slot))
        if await self._has_block(ctx, slot):
            _LOG.debug("%s, FOUND the slot %s with the block", ctx.caption, slot)
            return slot or 0

        # resolve the bad situation, when the Solana node has list of blocks, by they are empty
        slot = await self._bisect_left(ctx)
        if await self._has_block(ctx, slot):
            _LOG.debug("%s, FOUND the slot %s with the block", ctx.caption, slot)
            return slot or 0

        _LOG.warning("%s, NO not-empty slots in the range", ctx.caption)
        return 0

    async def get_stop_slot(self) -> int:
        return await self._get_stop_slot()

    async def _bisect_left(self, ctx: _Ctx) -> int:
        """
        Return the index of the first not-empty slot.
        Copy-paste of the bisect_left from the py 3.7, but it supports the async getting of the value,
        """
        start_slot, stop_slot = ctx.start_slot, ctx.stop_slot
        while start_slot < stop_slot:
            mid_slot = (start_slot + stop_slot) // 2
            # find the first slot and the last available slot in the range: mid_slot, mid_slot + 1024
            mid_ctx = _Ctx(mid_slot, stop_slot)
            start_mid_slot = await self._find_slot(mid_ctx)
            if not (await self._has_block(mid_ctx, start_mid_slot)):
                start_slot = mid_slot + 1
            else:
                stop_slot = mid_slot
        return start_slot

    async def _has_block(self, ctx: _Ctx, slot: int | None) -> bool:
        if slot is None:
            return False

        if is_empty := (await self._sol_client.get_block(slot, SolCommit.Finalized)).is_empty:
            _LOG.debug("%s, SKIP the empty slot %s...", ctx.caption, slot)
        else:
            _LOG.debug("%s, FOUND the not-empty slot %s...", ctx.caption, slot)
        return not is_empty

    async def _find_slot(self, ctx: _Ctx) -> int | None:
        stop_slot = min(ctx.stop_slot, ctx.start_slot + 999)
        if slot_list := await self._sol_client.get_slot_list(ctx.start_slot, stop_slot, SolCommit.Finalized):
            return slot_list[0]
        return None

    async def _get_start_slot(self) -> int:
        return self._def_start_slot or 5

    @cached_method
    async def _get_stop_slot(self) -> int:
        return self._def_stop_slot or await self._sol_client.get_slot(SolCommit.Finalized)


class SolFirstBlockFinder(SolNotEmptyBlockFinder):
    def __init__(self, sol_client: SolClient):
        super().__init__(sol_client)

    @cached_method
    async def _get_start_slot(self) -> int:
        if self._def_start_slot:
            return self._def_start_slot

        first_slot = await self._sol_client.get_first_slot()
        if first_slot > 0:
            # in any case the solana doesn't have a full history
            # so, the Indexer can skip first 8192 blocks
            # the reason is to skip the working on edge case
            first_slot += 8192
        else:
            # for the local stand with a test-validator, which doesn't have blocks in slots 2 and 3
            first_slot = 5
        return first_slot


@dataclass(frozen=True)
class _Ctx:
    start_slot: int
    stop_slot: int

    @cached_property
    def caption(self) -> str:
        return f"range {self.start_slot, self.stop_slot}"

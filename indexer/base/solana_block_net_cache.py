from __future__ import annotations

import asyncio
import logging
from typing import Generator

from common.config.config import Config
from common.solana.block import SolRpcBlockInfo
from common.solana_rpc.client import SolClient
from .errors import SolHistoryError, SolFailedHistoryError
from .objects import SolNeonDecoderCtx

_LOG = logging.getLogger(__name__)


class SolBlockNetCache:
    def __init__(self, cfg: Config, sol_client: SolClient):
        self._cfg = cfg
        self._sol_client = sol_client

        self._slot_request_len = cfg.indexer_poll_block_cnt * 4
        self._block_request_len = cfg.indexer_poll_block_cnt

        self._start_slot = -1
        self._stop_slot = -1
        self._block_list: list[SolRpcBlockInfo] = list()

    def finalize_block(self, slot: int) -> None:
        if slot > self._stop_slot:
            _LOG.debug("clear on finalized slot: %s", slot)
            self._clear_cache()
            return
        elif slot <= self._start_slot:
            return

        idx = self._calc_idx(slot)
        self._block_list = self._block_list[idx:]
        self._start_slot = slot

    async def iter_block(self, ctx: SolNeonDecoderCtx) -> Generator[SolRpcBlockInfo, None, None]:
        head_block: SolRpcBlockInfo | None = None
        root_slot = base_slot = ctx.start_slot

        while base_slot < ctx.stop_slot:
            slot_list = await self._cache_block_list(ctx, base_slot)
            base_slot = slot_list[-1]

            if not (block_queue := self._build_block_queue(ctx, root_slot, base_slot)):
                continue

            # skip the root-slot, include it in the next queue (like start-slot)
            head_block, block_queue = block_queue[0], block_queue[1:]
            root_slot = head_block.slot
            for sol_block in reversed(block_queue):
                yield sol_block

        if root_slot != ctx.stop_slot:
            self._raise_error(ctx, ctx.stop_slot, f"Failed to reach head {root_slot} (!= {ctx.stop_slot})")

        # in the loop there were the skipping of the root-slot, now return last one
        if head_block:
            yield head_block

    def _build_block_queue(self, ctx: SolNeonDecoderCtx, root_slot: int, slot: int) -> tuple[SolRpcBlockInfo, ...]:
        child_slot = 0
        block_queue: list[SolRpcBlockInfo] = list()
        while slot >= root_slot:
            sol_block = self._get_sol_block(slot)
            if sol_block.is_empty:
                self._raise_error(ctx, slot, f"Failed to get block {slot} (for child {child_slot})")

            block_queue.append(sol_block)
            if slot == root_slot:
                return tuple(block_queue)
            slot = sol_block.parent_slot
            child_slot = sol_block.slot

        self._raise_error(ctx, root_slot, f"Failed to reach root {root_slot} (!= {slot})")

    def _get_sol_block(self, slot: int) -> SolRpcBlockInfo:
        idx = self._calc_idx(slot)
        sol_block = self._block_list[idx]
        assert sol_block.slot == slot
        return sol_block

    @staticmethod
    def _raise_error(ctx: SolNeonDecoderCtx, slot: int, msg: str) -> None:
        if (not ctx.is_finalized) or ((ctx.stop_slot - slot) < 512):
            raise SolHistoryError(msg)
        raise SolFailedHistoryError(slot, msg)

    async def _cache_block_list(self, ctx: SolNeonDecoderCtx, base_slot: int) -> tuple[int, ...]:
        slot_list = await self._get_slot_list(ctx, base_slot)
        self._extend_cache_with_empty_blocks(ctx, base_slot, slot_list)

        # request blocks for empty slots
        empty_slot_list = [slot for slot in slot_list if self._get_sol_block(slot).is_empty]
        if not len(empty_slot_list):
            return slot_list

        block_list = await asyncio.gather(
            *[self._sol_client.get_block(slot, ctx.sol_commit) for slot in empty_slot_list]
        )
        for block in block_list:
            idx = self._calc_idx(block.slot)
            if not block.is_empty:
                self._block_list[idx] = block
                #  _LOG.debug("load block: %s", block.slot)
        return slot_list

    def _extend_cache_with_empty_blocks(
        self, ctx: SolNeonDecoderCtx, base_slot: int, slot_list: tuple[int, ...]
    ) -> None:
        assert slot_list[0] >= base_slot

        # if the requested range doesn't continue the range of the cached blocks
        if base_slot > self._stop_slot + 1:
            _LOG.debug("clear on start slot: %s", ctx)
            self._clear_cache()
        else:
            base_slot = self._stop_slot + 1

        # the requested range in the range of the cached blocks
        if (stop_slot := slot_list[-1] + 1) <= base_slot:
            return

        # extend the cache with empty blocks
        self._block_list.extend(SolRpcBlockInfo.new_empty(slot) for slot in range(base_slot, stop_slot))
        self._start_slot = self._block_list[0].slot
        self._stop_slot = self._block_list[-1].slot

    def _clear_cache(self) -> None:
        self._start_slot = -1
        self._stop_slot = -1
        self._block_list.clear()

    def _calc_idx(self, slot: int) -> int:
        return slot - self._start_slot

    async def _get_slot_list(self, ctx: SolNeonDecoderCtx, base_slot: int) -> tuple[int, ...]:
        stop_slot = self._calc_stop_slot(ctx, base_slot)
        if len(slot_list := await self._sol_client.get_slot_list(base_slot, stop_slot, ctx.sol_commit)) < 2:
            self._raise_error(ctx, base_slot, f"No slots after the slot {base_slot}")

        if ctx.is_finalized:
            slot_list = slot_list[: self._block_request_len]
        return slot_list

    def _calc_stop_slot(self, ctx: SolNeonDecoderCtx, base_slot: int) -> int:
        if not ctx.is_finalized:
            return ctx.stop_slot

        return min(base_slot + self._slot_request_len, ctx.stop_slot)

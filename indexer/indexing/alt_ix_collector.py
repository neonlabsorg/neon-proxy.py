from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Final

from common.config.config import Config
from common.neon.transaction_decoder import SolNeonAltTxIxModel
from common.solana.alt_program import SolAltProg, SolAltIxCode
from common.solana.commit_level import SolCommit
from common.solana.signature import SolTxSig
from common.solana.transaction_decoder import SolTxMetaInfo, SolTxIxMetaInfo
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedAltInfo

_LOG = logging.getLogger(__name__)


class SolAltTxIxCollector:
    _block_step_cnt: Final[int] = (512 + 32 * 3) // 2  # 512 blocks for ALT closing, 32 blocks for finalization

    def __init__(self, cfg: Config, sol_client: SolClient):
        self._cfg = cfg
        self._sol_client = sol_client
        self._next_check_slot = self._block_step_cnt
        self._fail_check_slot = 0

    @cached_property
    def check_depth(self) -> int:
        return self._cfg.alt_freeing_depth * 20

    async def collect_in_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if neon_block.slot < self._next_check_slot:
            return
        elif not (alt_list := self._filter_alt_list(neon_block)):
            return
        await asyncio.gather(*[self._check_alt(_Ctx(neon_block, alt)) for alt in alt_list])

    def _filter_alt_list(self, neon_block: NeonIndexedBlockInfo) -> list[NeonIndexedAltInfo]:
        self._fail_check_slot = neon_block.slot - self.check_depth
        self._next_check_slot = next_check_slot = neon_block.slot + self._block_step_cnt

        alt_list: list[NeonIndexedAltInfo] = list()
        for alt in neon_block.iter_alt():
            if alt.next_check_slot > neon_block.slot:
                continue
            alt_list.append(alt)
            alt.set_next_check_slot(next_check_slot)
        return alt_list

    async def _check_alt(self, ctx: _Ctx) -> None:
        is_done = await self._has_done_in_alt_ix_list(ctx)
        if (not is_done) and (ctx.alt.last_sol_ix_slot < self._fail_check_slot):
            is_done = await self._has_done_in_alt_acct(ctx)

        if is_done:
            ctx.neon_block.done_alt(ctx.alt)

    async def _has_done_in_alt_ix_list(self, ctx: _Ctx) -> bool:
        if not (tx_sig_list := await self._get_tx_sig_list(ctx)):
            return False

        is_done = False
        for tx_sig in tx_sig_list:
            rpc_tx = await self._sol_client.get_tx(tx_sig, SolCommit.Finalized)
            tx = SolTxMetaInfo.from_raw(rpc_tx.slot, rpc_tx.transaction)

            for tx_ix in tx.sol_ix_list:
                is_done |= self._has_done_in_alt_ix(ctx, tx, tx_ix)
                for tx_inner_ix in tx.sol_inner_ix_list(tx_ix):
                    is_done |= self._has_done_in_alt_ix(ctx, tx, tx_inner_ix)

        return is_done

    async def _get_tx_sig_list(self, ctx: _Ctx) -> tuple[SolTxSig, ...]:
        last_slot = ctx.alt.last_sol_ix_slot
        rpc_tx_sig_list = await self._sol_client.get_tx_sig_list(ctx.alt.address, 1000, SolCommit.Finalized)
        return tuple([SolTxSig.from_raw(rpc_sig.signature) for rpc_sig in rpc_tx_sig_list if rpc_sig.slot > last_slot])

    @staticmethod
    def _has_done_in_alt_ix(ctx: _Ctx, tx: SolTxMetaInfo, tx_ix: SolTxIxMetaInfo) -> bool:
        if tx_ix.prog_id != SolAltProg.ID:
            return False
        elif not (alt_ix := SolNeonAltTxIxModel.from_raw(tx, tx_ix, ctx.alt.neon_tx_hash)):
            return False

        ctx.neon_block.add_alt_ix(ctx.alt, alt_ix)
        if alt_ix.alt_ix_code == SolAltIxCode.Freeze:
            _LOG.warning("ALT %s is frozen", ctx.alt)
            return True
        return alt_ix.alt_ix_code == SolAltIxCode.Close

    async def _has_done_in_alt_acct(self, ctx: _Ctx) -> bool:
        if not (alt := await self._sol_client.get_alt_account(ctx.alt.address, commit=SolCommit.Finalized)).is_exist:
            return True

        if not alt.owner:
            _LOG.warning("ALT %s is frozen", ctx.alt)
            return True

        # don't wait for ALTs from other operators
        return False


@dataclass(frozen=True)
class _Ctx:
    neon_block: NeonIndexedBlockInfo
    alt: NeonIndexedAltInfo

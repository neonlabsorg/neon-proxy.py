from typing import Sequence

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_base import BaseTxPrepStage


class WriteHolderTxPrepStage(BaseTxPrepStage):
    async def make_ix_list(self) -> Sequence[SolTxIx]:
        if self._ctx.is_started_tx:
            return tuple()

        return self._ctx.neon_prog.make_write_ix_list()

    async def prep_execution(self) -> bool:
        return True

    def _get_ix_name_list(self) -> Sequence[str]:
        if self._ctx.is_started_tx:
            return tuple()
        return tuple([NeonEvmIxCode.HolderWrite.name])

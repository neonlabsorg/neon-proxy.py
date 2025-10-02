from typing import ClassVar, Sequence

from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import HolderAccountStatus
from common.solana.cb_program import SolCbProg, SolCbCfg
from common.solana.transaction import SolTx
from .strategy_base import BaseTxPrepStage


class WriteHolderTxPrepStage(BaseTxPrepStage):
    name: ClassVar[str] = NeonEvmIxCode.HolderWrite.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_status = HolderAccountStatus.Empty

    def get_tx_name_list(self) -> Sequence[str]:
        if self._ctx.is_stuck_tx:
            return tuple()
        return tuple([self.name])

    async def make_tx_list(self) -> Sequence[Sequence[SolTx]]:
        if self._ctx.is_stuck_tx or (self._ctx.good_sol_tx_cnt(self.name) > 0):
            return list()

        neon_prog = self._ctx.neon_prog

        cb_cfg = SolCbCfg(self.name, cu_price=self._cu_price, cu_limit=neon_prog.CuLimitHolderWrite)

        tx_list = map(
            lambda ix: SolCbProg.make_legacy_tx(cb_cfg, ix),
            neon_prog.make_write_ix_list(),
        )
        return [list(tx_list)]

    async def prep_before_exec(self) -> bool:
        return True

from typing import Final, ClassVar, Sequence

from common.neon.neon_program import NeonEvmIxCode
from common.neon.transaction_model import NeonSkdTxStatus
from common.solana.instruction import SolTxIx
from common.utils.cached import cached_property
from proxy.executor.strategy_iterative import IterativeTxStrategy
from proxy.executor.strategy_stage_alt import alt_strategy


class ScheduledTxStrategy(IterativeTxStrategy):
    Name: ClassVar[str] = "Skd+" + NeonEvmIxCode.TxStepFromData.name
    _StartSkdTxIxName: ClassVar[str] = NeonEvmIxCode.SkdTxStartFromData.name
    _SkipSkdTxIxName: ClassVar[str] = NeonEvmIxCode.SkdTxSkipFromData.name
    _FinishSkdTxIxName: Final[str] = NeonEvmIxCode.SkdTxFinish.name

    async def _validate(self) -> bool:
        return (
            self._validate_skd_tx()
            and self._validate_has_chain_id()
            and self._validate_neon_tx_size()
        )

    async def prep_execution(self) -> bool:
        if not await super().prep_execution():
            return False

        return await self._start_skd_tx()

    async def done_execution(self) -> None:
        ix: Final = self._make_finish_skd_tx_ix()
        exec_status: Final = (NeonSkdTxStatus.InProgress,)

        await self._send_sol_skd_tx(ix, exec_status)

    async def _start_skd_tx(self) -> bool:
        exec_status: Final = (NeonSkdTxStatus.ToStart, NeonSkdTxStatus.ToSkip)

        if (status := await self._ctx.get_skd_tx_status()) == NeonSkdTxStatus.ToStart:
            ix: Final = self._make_start_skd_tx_ix()
        elif status == NeonSkdTxStatus.ToSkip:
            ix: Final = self._make_skip_skd_tx_ix()
        else:
            return True

        return await self._send_sol_skd_tx(ix, exec_status)

    async def _send_sol_skd_tx(self, ix: SolTxIx, exec_status: Sequence[NeonSkdTxStatus]) -> bool:
        tx_cfg: Final = self._init_sol_neon_tx_cfg()

        try:
            while True:
                if await self._ctx.get_skd_tx_status() not in exec_status:
                    return True
                elif await self._ctx.recheck_sol_tx_list(ix.name):
                    return True
                elif await self._send_sol_tx_list(ix, tx_cfg):
                    return True
        finally:
            await self._find_neon_tx_status()

    def _make_finish_skd_tx_ix(self) -> SolTxIx:
        return self._ctx.neon_prog.make_finish_skd_tx_ix(self._ctx.skd_tx_idx)

    def _make_start_skd_tx_ix(self) -> SolTxIx:
        return self._ctx.neon_prog.make_start_skd_tx_from_data_ix(self._ctx.skd_tx_idx)

    def _make_skip_skd_tx_ix(self) -> SolTxIx:
        return self._ctx.neon_prog.make_skip_skd_tx_from_data_ix(self._ctx.skd_tx_idx)

    @cached_property
    def _ix_name_list(self) -> Sequence[str]:
        return tuple([self.Name, self._StartSkdTxIxName, self._SkipSkdTxIxName, self._FinishSkdTxIxName])


@alt_strategy
class AltScheduledTxStrategy(ScheduledTxStrategy): ...

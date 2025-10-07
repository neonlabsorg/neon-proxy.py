from typing import ClassVar, Final

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_iterative import SolNeonIterTxCfg
from .strategy_iterative_scheduled import ScheduledTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class ScheduledHolderTxStrategy(ScheduledTxStrategy):
    Name: ClassVar[str] = "Skd+" + NeonEvmIxCode.TxStepFromAccount.name
    _StartSkdTxIxName: ClassVar[str] = NeonEvmIxCode.SkdTxStartFromAccount.name
    _SkipSkdTxIxName: ClassVar[str] = NeonEvmIxCode.SkdTxSkipFromAccount.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(WriteHolderTxPrepStage(*args, **kwargs))

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_skd_tx()
            and self._validate_has_chain_id()
        )
        # fmt: on

    def _make_neon_ix(self, tx_cfg = SolNeonIterTxCfg) -> SolTxIx:
        uniq_idx: Final = next(self._uniq_idx)
        return self._ctx.neon_prog.make_tx_step_from_account_ix(tx_cfg.ix_mode, tx_cfg.evm_step_cnt, uniq_idx)

    def _make_start_skd_tx_ix(self) -> SolTxIx:
        return self._ctx.neon_prog.make_start_skd_tx_from_account_ix(self._ctx.skd_tx_idx)

    def _make_skip_skd_tx_ix(self) -> SolTxIx:
        return self._ctx.neon_prog.make_skip_skd_tx_from_account_ix(self._ctx.skd_tx_idx)


@alt_strategy
class AltScheduledHolderTxStrategy(ScheduledHolderTxStrategy): ...

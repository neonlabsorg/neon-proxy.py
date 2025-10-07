from typing import ClassVar, Final

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_iterative import IterativeTxStrategy, SolNeonIterTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class HolderTxStrategy(IterativeTxStrategy):
    Name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccount.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(WriteHolderTxPrepStage(*args, **kwargs))

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_has_chain_id()
            and self._validate_not_skd_tx()
        )
        # fmt: on

    def _make_neon_ix(self, tx_cfg = SolNeonIterTxCfg) -> SolTxIx:
        uniq_idx: Final = next(self._uniq_idx)
        return self._ctx.neon_prog.make_tx_step_from_account_ix(tx_cfg.ix_mode, tx_cfg.evm_step_cnt, uniq_idx)


@alt_strategy
class AltHolderTxStrategy(HolderTxStrategy): ...

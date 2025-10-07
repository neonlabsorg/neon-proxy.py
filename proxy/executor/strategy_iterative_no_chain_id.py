from typing import ClassVar, Final

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_iterative import SolNeonIterTxCfg
from .strategy_iterative_holder import HolderTxStrategy
from .strategy_stage_alt import alt_strategy


class NoChainIdTxStrategy(HolderTxStrategy):
    Name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccountNoChainId.name

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_skd_tx()
            and self._validate_no_chain_id()
        )
        # fmt: on

    def _make_neon_ix(self, tx_cfg: SolNeonIterTxCfg) -> SolTxIx:
        step_cnt: Final = tx_cfg.evm_step_cnt
        ix_mode: Final = tx_cfg.ix_mode
        uniq_idx: Final = next(self._uniq_idx)
        return self._ctx.neon_prog.make_tx_step_from_account_no_chain_id_ix(ix_mode, step_cnt, uniq_idx)

    def _validate_no_chain_id(self) -> bool:
        if not self._ctx.has_chain_id:
            return True

        self._validation_error_msg = "Normal transaction"
        return False


@alt_strategy
class AltNoChainIdTxStrategy(NoChainIdTxStrategy): ...

from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_iterative import SolIterListCfg
from .strategy_iterative_holder import HolderTxStrategy
from .strategy_stage_alt import alt_strategy


class NoChainIdTxStrategy(HolderTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccountNoChainId.name

    async def _validate(self) -> bool:
        if self._ctx.has_chain_id:
            self._validation_error_msg = "Normal transaction"
            return False
        return self._validate_no_sol_call()

    def _build_tx_ix(self, tx_cfg: SolIterListCfg) -> SolTxIx:
        step_cnt = tx_cfg.evm_step_cnt
        ix_mode = tx_cfg.ix_mode
        uniq_idx = self._ctx.next_uniq_idx()
        return self._ctx.neon_prog.make_tx_step_from_account_no_chain_id_ix(ix_mode, step_cnt, uniq_idx)


@alt_strategy
class AltNoChainIdTxStrategy(NoChainIdTxStrategy):
    pass

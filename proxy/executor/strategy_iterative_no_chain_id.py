from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_iterative_holder import HolderTxStrategy
from .strategy_stage_alt import alt_strategy


class NoChainIdTxStrategy(HolderTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccountNoChainId.name

    async def _validate(self) -> bool:
        if self._ctx.has_chain_id:
            self._validation_error_msg = "Normal transaction"
            return False
        return self._validate_no_sol_call()

    def _build_tx(self, *, mode: NeonIxMode = NeonIxMode.Default, step_cnt: int = 0) -> SolLegacyTx:
        step_cnt = step_cnt or self._ctx.evm_step_cnt_per_iter
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_account_no_chain_id_ix(mode, step_cnt, uniq_idx))


@alt_strategy
class AltNoChainIdTxStrategy(NoChainIdTxStrategy):
    pass

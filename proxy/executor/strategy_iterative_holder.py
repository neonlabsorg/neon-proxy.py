from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_iterative import IterativeTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class HolderTxStrategy(IterativeTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccount.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._write_holder_stage = WriteHolderTxPrepStage(*args, **kwargs)
        self._prep_stage_list.append(self._write_holder_stage)

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_has_chain_id()
            and self._validate_no_sol_call()
        )
        # fmt: on

    def _build_tx(self, *, is_finalized: bool = False, step_cnt: int = 0) -> SolLegacyTx:
        step_cnt = step_cnt or self._def_evm_step_cnt
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_account_ix(is_finalized, step_cnt, uniq_idx))


@alt_strategy
class AltHolderTxStrategy(HolderTxStrategy):
    pass

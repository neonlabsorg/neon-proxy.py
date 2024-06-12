from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from .strategy_iterative_holder import HolderTxStrategy
from .strategy_stage_alt import alt_strategy


class HolderTxSolanaCallStrategy(HolderTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccount.name + "+SolanaCall"

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_stuck_tx()
            and self._validate_has_chain_id()
            and self._validate_has_sol_call()
        )
        # fmt: on


@alt_strategy
class AltHolderTxSolanaCallStrategy(HolderTxSolanaCallStrategy):
    pass

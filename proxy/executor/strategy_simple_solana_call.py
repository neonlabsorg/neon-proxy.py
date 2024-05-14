from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_simple import SimpleTxStrategy
from .strategy_stage_alt import alt_strategy


class SimpleTxSolanaCallStrategy(SimpleTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxExecFromDataSolanaCall.name

    async def _validate(self) -> bool:
        return (
            self._validate_not_stuck_tx()
            and self._validate_has_chain_id()
            and self._validate_has_sol_call()
            and self._validate_no_resize_iter()
        )

    def _build_tx(self, **kwargs) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_tx_exec_from_data_solana_call_ix())


@alt_strategy
class AltSimpleTxSolanaCallStrategy(SimpleTxSolanaCallStrategy):
    pass

from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_simple import SimpleTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class SimpleHolderTxStrategy(SimpleTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxExecFromAccount.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(WriteHolderTxPrepStage(*args, **kwargs))

    def _build_tx(self, **kwargs) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_tx_exec_from_account_ix())


@alt_strategy
class AltSimpleHolderTxStrategy(SimpleHolderTxStrategy):
    pass

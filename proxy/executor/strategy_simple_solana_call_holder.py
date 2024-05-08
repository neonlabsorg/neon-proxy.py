from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_simple_solana_call import SimpleTxSolanaCallStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class SimpleHolderTxSolanaCallStrategy(SimpleTxSolanaCallStrategy):
    name = NeonEvmIxCode.TxExecFromAccountSolanaCall.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(WriteHolderTxPrepStage(*args, **kwargs))

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_tx_exec_from_account_solana_call_ix())


@alt_strategy
class AltSimpleHolderTxSolanaCallStrategy(SimpleHolderTxSolanaCallStrategy):
    pass

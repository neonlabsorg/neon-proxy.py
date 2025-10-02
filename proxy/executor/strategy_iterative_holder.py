from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_iterative import IterativeTxStrategy, SolNeonIterTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_write_holder import WriteHolderTxPrepStage


class HolderTxStrategy(IterativeTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccount.name
    _start_skd_tx_name: ClassVar[str] = NeonEvmIxCode.SkdTxStartFromAccount.name
    _skip_skd_tx_name: ClassVar[str] = NeonEvmIxCode.SkdTxSkipFromAccount.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._write_holder_stage = WriteHolderTxPrepStage(*args, **kwargs)
        self._prep_stage_list.append(self._write_holder_stage)

    async def _validate(self) -> bool:
        return self._validate_has_chain_id()

    def _make_neon_ix(self, tx_cfg: SolNeonIterTxCfg) -> SolTxIx:
        step_cnt = tx_cfg.evm_step_cnt
        uniq_idx = self._ctx.next_uniq_idx()
        return self._ctx.neon_prog.make_tx_step_from_account_ix(tx_cfg.ix_mode, step_cnt, uniq_idx)

    def _make_start_skd_tx_ix(self, index: int) -> SolTxIx:
        return self._ctx.neon_prog.make_start_skd_tx_from_account_ix(index)

    def _make_skip_skd_tx_ix(self, index: int) -> SolTxIx:
        return self._ctx.neon_prog.make_skip_skd_tx_from_account_ix(index)


@alt_strategy
class AltHolderTxStrategy(HolderTxStrategy):
    pass

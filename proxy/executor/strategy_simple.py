from __future__ import annotations

import logging
from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .errors import WrongStrategyError
from .strategy_base import BaseTxStrategy, SolNeonTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)


class SimpleTxStrategy(BaseTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxExecFromData.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))

    async def execute(self) -> ExecTxDoneCode:
        assert self.is_valid

        if not await self._recheck_tx_list(self.name):
            base_cfg = self._init_sol_neon_tx_cfg()
            ix = self._make_neon_ix(base_cfg)
            await self._emulate_and_send_single_tx("simple", ix, base_cfg)

        tx_send_state_list = self._ctx.sol_tx_list_sender.success_tx_state_list
        for tx_state in tx_send_state_list:
            if tx_state.is_finalized:
                _LOG.debug("found NeonTx-Return in %s", tx_state.tx)
                return ExecTxDoneCode.Done
            else:
                _LOG.warning("truncated!? NeonTx-Return in %s", tx_state.tx)
                return ExecTxDoneCode.Done

        _LOG.debug("failed!? NeonTx-Return, try next strategy...")
        raise WrongStrategyError()

    def _make_neon_ix(self, tx_cfg: SolNeonTxCfg) -> SolTxIx:
        return self._ctx.neon_prog.make_tx_exec_from_data_ix()

    async def _validate(self) -> bool:
        return (
            self._validate_not_stuck_tx()
            and self._validate_not_scheduled_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
            and self._validate_no_resize_iter()
            and self._validate_neon_tx_size()
        )


@alt_strategy
class AltSimpleTxStrategy(SimpleTxStrategy):
    pass

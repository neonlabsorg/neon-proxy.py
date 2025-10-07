from __future__ import annotations

import logging
from typing import ClassVar, Final

from common.neon.cancel_error import CancelErrorData
from common.neon.evm_log_decoder import NeonTxLogReturnInfo, NeonTxEventModel
from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .errors import WrongStrategyError
from .strategy_base import BaseTxStrategy, SolNeonTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from .transaction_executor_ctx import NeonExecTxState
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)


class SimpleTxStrategy(BaseTxStrategy):
    Name: ClassVar[str] = NeonEvmIxCode.TxExecFromData.name
    IsSimple: ClassVar[bool] = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))

    async def execute(self) -> ExecTxDoneCode:
        assert self.is_valid

        if not await self._ctx.recheck_sol_tx_list(self.Name):
            await self._exec_neon_tx()

        return await self._find_neon_tx_return()

    async def cancel(self, data: CancelErrorData) -> ExecTxDoneCode | None: ...  # do nothing

    async def done_execution(self) -> None: ...  # do nothing

    def _make_neon_ix(self, tx_cfg: SolNeonTxCfg) -> SolTxIx:
        return self._ctx.neon_prog.make_tx_exec_from_data_ix()

    async def _validate(self) -> bool:
        return (
            self._validate_not_skd_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
            and self._validate_no_resize_iter()
            and self._validate_neon_tx_size()
        )

    async def _exec_neon_tx(self) -> None:
        tx_cfg: Final = self._init_sol_neon_tx_cfg()
        exec_ix: Final = self._make_neon_ix(tx_cfg)
        await self._send_sol_tx_list(exec_ix, tx_cfg)

    async def _find_neon_tx_return(self) -> ExecTxDoneCode:
        tx_send_state_list = self._ctx.get_sol_tx_state_list(self.Name)
        for tx_state in tx_send_state_list:
            if tx_state.is_finalized:
                _LOG.debug("found %s in %s", tx_state.neon_tx_return, tx_state.tx)
                await self._ctx.set_tx_exec_state(NeonExecTxState.from_tx_return(tx_state.neon_tx_return))
                return ExecTxDoneCode.Done
            else:
                _LOG.warning("truncated!? NeonTx.Return in %s", tx_state.tx)
                tx_return = NeonExecTxState.from_tx_return(NeonTxLogReturnInfo(NeonTxEventModel.Type.Lost, 0))
                await self._ctx.set_tx_exec_state(tx_return)
                return ExecTxDoneCode.Done

        _LOG.debug("failed!? NeonTx.Return, try next strategy...")
        raise WrongStrategyError()


@alt_strategy
class AltSimpleTxStrategy(SimpleTxStrategy): ...

from __future__ import annotations

import logging

from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.transaction_list_sender import SolTxSendState
from ..base.ex_api import ExecTxRespCode
from .errors import WrongStrategyError
from .strategy_base import BaseTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage

_LOG = logging.getLogger(__name__)


class SimpleTxStrategy(BaseTxStrategy):
    name = NeonEvmIxCode.TxExecFromData.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if not await self._recheck_tx_list(self.name):
            await self._send_tx_list(self._build_tx_list())

        tx_send_state_list = self._ctx.sol_tx_list_sender.tx_state_list
        tx_state = tx_send_state_list[0]
        status = SolTxSendState.Status

        if tx_state.status == status.GoodReceipt:
            if not (sol_neon_ix := self._find_sol_neon_ix(tx_state)):
                _LOG.warning("no!? NeonTx instruction in %s", tx_state.tx)
                return ExecTxRespCode.Failed
            elif not sol_neon_ix.neon_tx_return.is_empty:
                _LOG.debug("found NeonTx-Return in %s", tx_state.tx)
                return ExecTxRespCode.Done
            else:
                _LOG.warning("truncated!? NeonTx-Return in %s", tx_state.tx)
                return ExecTxRespCode.Failed

        _LOG.debug("no!? NeonTx-Return in %s(%s), try next strategy...", tx_state.tx, tx_state.status.name)
        raise WrongStrategyError()

    async def cancel(self) -> None:
        _LOG.debug("canceling of simple NeonTx, force to switch to next strategy...")
        return None

    def _build_tx_list(self) -> list[SolLegacyTx]:
        return [self._build_tx()]

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_tx_exec_from_data_ix())

    async def _validate(self) -> bool:
        return (
            self._validate_not_stuck_tx() and
            self._validate_no_sol_call() and
            self._validate_has_chain_id()
        )


@alt_strategy
class AltSimpleTxStrategy(SimpleTxStrategy):
    pass

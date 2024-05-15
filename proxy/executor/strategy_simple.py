from __future__ import annotations

import logging
from typing import Final, ClassVar

from common.neon.neon_program import NeonEvmIxCode
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import SolCbExceededError
from common.solana_rpc.transaction_list_sender import SolTxSendState
from .errors import WrongStrategyError
from .strategy_base import BaseTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from ..base.ex_api import ExecTxRespCode

_LOG = logging.getLogger(__name__)


class SimpleTxStrategy(BaseTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxExecFromData.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if not await self._recheck_tx_list(self.name):
            await self._emulate_and_send_tx_list()

        tx_send_state_list = self._ctx.sol_tx_list_sender.tx_state_list
        status = SolTxSendState.Status

        for tx_state in tx_send_state_list:
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

        _LOG.debug("no!? NeonTx-Return, try next strategy...")
        raise WrongStrategyError()

    async def cancel(self) -> None:
        _LOG.debug("canceling of a simple NeonTx...")
        return None

    async def _emulate_and_send_tx_list(self) -> bool:
        tx_list = tuple([self._build_tx()])

        emul_tx_list = await self._emulate_tx_list(tx_list)
        used_cu_limit = max(map(lambda x: x.meta.used_cu_limit, emul_tx_list))

        # let's decrease the available cu-limit on 5% percents
        safe_cu_limit_add: Final[int] = int(self._cu_limit * 0.05)
        total_used_cu_limit = max(used_cu_limit + safe_cu_limit_add, self._cu_limit)

        if total_used_cu_limit > self._cu_limit:
            _LOG.debug(
                "got %s(+%s) CUs for %s EVM steps, and it's bigger than the upper limit %s",
                used_cu_limit,
                safe_cu_limit_add,
                self._ctx.total_evm_step_cnt,
                self._cu_limit,
            )
            raise SolCbExceededError()

        _LOG.debug("got %s CUs for %s EVM steps", used_cu_limit, self._ctx.total_evm_step_cnt)
        tx_list = tuple(map(lambda x: x.tx, emul_tx_list))
        return await self._send_tx_list(tx_list)

    def _build_tx(self, **kwargs) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_tx_exec_from_data_ix())

    async def _validate(self) -> bool:
        return (
            self._validate_not_stuck_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
            and self._validate_no_resize_iter()
        )


@alt_strategy
class AltSimpleTxStrategy(SimpleTxStrategy):
    pass

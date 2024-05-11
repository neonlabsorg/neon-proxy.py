from __future__ import annotations

import logging
from typing import ClassVar

from common.neon_rpc.api import HolderAccountStatus
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context
from .errors import StuckTxError
from .server_abc import ExecutorApi
from .transaction_executor import NeonTxExecutor
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxRequest, ExecTxResp, ExecStuckTxRequest, ExecTxRespCode
from ..base.mp_api import MpStuckTxModel
from ..base.server import BaseProxyApi

_LOG = logging.getLogger(__name__)


class NeonTxExecApi(ExecutorApi):
    name: ClassVar[str] = "Executor::Transaction"

    @BaseProxyApi.method(name="executeNeonTransaction")
    async def exec_neon_tx(self, tx_request: ExecTxRequest) -> ExecTxResp:
        tx = tx_request.tx
        with logging_context(tx=tx.tx_id):
            ctx = self._new_neon_exec_ctx(tx_request)

            while True:  # for the case when holder has a stuck NeonTx
                try:
                    return await self._neon_tx_executor.exec_neon_tx(ctx)
                except StuckTxError as exc:
                    _LOG.debug("switch to complete the stuck NeonTx %s", exc.neon_tx_hash)

                    # reset token_address, because the tx can be in another chain-id space
                    resource = tx_request.resource.model_copy(update=dict(token_sol_address=SolPubKey.default()))
                    stuck_tx = MpStuckTxModel.from_raw(exc.neon_tx_hash, exc.address)
                    req = ExecStuckTxRequest(stuck_tx=stuck_tx, resource=resource)
                    await self.complete_stuck_neon_tx(req)

                    _LOG.debug("return back to the execution of NeonTx %s", tx.neon_tx_hash)

                except BaseException as exc:
                    _LOG.error("unexpected error on execute NeonTx", exc_info=exc, extra=self._msg_filter)

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_neon_tx(self, tx_request: ExecStuckTxRequest) -> ExecTxResp:
        with logging_context(tx=tx_request.stuck_tx.tx_id):
            ctx = self._new_neon_exec_ctx(tx_request)
            try:
                return await self._neon_tx_executor.complete_stuck_neon_tx(ctx)
            except BaseException as exc:
                _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)
                return ExecTxResp(code=ExecTxRespCode.Failed)

    @property
    def _neon_tx_executor(self) -> NeonTxExecutor:
        return self._server._neon_tx_executor  # noqa

    def _new_neon_exec_ctx(self, tx_request: ExecTxRequest | ExecStuckTxRequest) -> NeonExecTxCtx:
        return NeonExecTxCtx(
            self._cfg,
            self._sol_client,
            self._core_api_client,
            self._op_client,
            tx_request,
        )

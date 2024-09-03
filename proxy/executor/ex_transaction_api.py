from __future__ import annotations

import logging
from typing import ClassVar

from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .alt_destroyer import SolAltDestroyer
from .errors import StuckTxError
from .server_abc import ExecutorApi
from .transaction_executor import NeonTxExecutor
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxRequest, ExecTxResp, ExecStuckTxRequest, ExecTxRespCode, NeonAltModel
from ..base.mp_api import MpStuckTxModel
from ..base.intl_server import BaseProxyApi

_LOG = logging.getLogger(__name__)


class NeonTxExecApi(ExecutorApi):
    name: ClassVar[str] = "Executor::Transaction"

    @BaseProxyApi.method(name="executeNeonTransaction")
    async def exec_neon_tx(self, tx_request: ExecTxRequest) -> ExecTxResp:
        tx = tx_request.tx
        ctx = self._new_neon_exec_ctx(tx_request)  # all created ALTs should be destroyed
        with logging_context(**ctx.req_id):
            while True:  # for the case when holder has a stuck NeonTx
                try:
                    resp = await self._neon_tx_executor.exec_neon_tx(ctx)
                    self._destroy_alt_list(ctx)
                    return resp

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
                    self._destroy_alt_list(ctx)
                    return ExecTxResp(code=ExecTxRespCode.Failed)

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_neon_tx(self, tx_request: ExecStuckTxRequest) -> ExecTxResp:
        ctx = self._new_neon_exec_ctx(tx_request)
        with logging_context(**ctx.req_id):
            try:
                return await self._neon_tx_executor.complete_stuck_neon_tx(ctx)
            except BaseException as exc:
                _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)
                return ExecTxResp(code=ExecTxRespCode.Failed)
            finally:
                self._destroy_alt_list(ctx)

    def _destroy_alt_list(self, ctx: NeonExecTxCtx) -> None:
        if ctx.alt_id_list:
            alt_list = tuple(map(lambda x: NeonAltModel(neon_tx_hash=ctx.neon_tx_hash, sol_alt_id=x), ctx.alt_id_list))
            self._sol_alt_destroyer.destroy_alt_list(alt_list)

    @cached_property
    def _neon_tx_executor(self) -> NeonTxExecutor:
        return self._server._neon_tx_executor  # noqa

    @cached_property
    def _sol_alt_destroyer(self) -> SolAltDestroyer:
        return self._server._sol_alt_destroyer  # noqa

    def _new_neon_exec_ctx(self, tx_request: ExecTxRequest | ExecStuckTxRequest) -> NeonExecTxCtx:
        return NeonExecTxCtx(
            self._cfg,
            self._sol_client,
            self._core_api_client,
            self._op_client,
            self._fee_client,
            self._stat_client,
            self._db,
            tx_request,
        )

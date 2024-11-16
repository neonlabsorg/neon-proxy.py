from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar, Final

from common.config.constants import ONE_BLOCK_SEC
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .alt_destroyer import SolAltDestroyer
from .errors import StuckTxError, BadResourceError
from .server_abc import ExecutorApi
from .transaction_executor import NeonTxExecutor
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxRequest, ExecTxResp, ExecStuckTxRequest, ExecTxRespCode, NeonAltModel
from ..base.intl_server import BaseProxyApi
from ..base.mp_api import MpStuckTxModel
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


class NeonTxExecApi(ExecutorApi):
    name: ClassVar[str] = "Executor::Transaction"
    _fail_sleep_sec: Final[float] = ONE_BLOCK_SEC / 4

    @BaseProxyApi.method(name="executeNeonTransaction")
    async def exec_neon_tx(self, tx_request: ExecTxRequest) -> ExecTxResp:
        resp_code = await self._exec_neon_tx(tx_request)
        state_tx_cnt = await self._core_api_client.get_state_tx_cnt(tx_request.sender, None)
        return ExecTxResp(code=resp_code, state_tx_cnt=state_tx_cnt)

    async def _exec_neon_tx(
        self,
        tx_request: ExecTxRequest,
    ) -> ExecTxRespCode:
        with logging_context(**tx_request.req_id):
            for retry in itertools.count():
                if retry > 0:
                    _LOG.debug("retry %d to execute NeonTx %s", retry, tx_request.tx.neon_tx_hash)
                if resp_code := await self._exec_neon_tx_impl(tx_request):
                    return resp_code

    async def _exec_neon_tx_impl(
        self,
        tx_request: ExecTxRequest,
    ) -> ExecTxRespCode | None:
        is_good_resource = True
        op_resource = await self._acquire_op_resource(tx_request)
        ctx = NeonExecTxCtx(self._server, op_resource, tx_request)

        try:
            return await self._neon_tx_executor.exec_neon_tx(ctx)

        except BadResourceError as exc:
            _LOG.warning("bad resource error: %s", str(exc))
            is_good_resource = False

        except StuckTxError as exc:
            _LOG.debug("switch to complete the stuck NeonTx %s", exc.neon_tx_hash)

            # re-request token_address, if the stuck tx is in different token space
            if exc.chain_id != op_resource.chain_id:
                token_sol_addr = await self._op_client.get_token_sol_address(
                    tx_request.req_id,
                    op_resource.owner,
                    exc.chain_id,
                )
                op_resource = op_resource.model_copy(update=dict(token_sol_address=token_sol_addr))

            stuck_tx = MpStuckTxModel.from_raw(exc.neon_tx_hash, exc.chain_id, exc.address)
            req = ExecStuckTxRequest(stuck_tx=stuck_tx, token=tx_request.token, op_resource=op_resource)
            await self.complete_stuck_neon_tx(req)

            _LOG.debug("return back to the execution of NeonTx %s", ctx.neon_tx_hash)

        except BaseException as exc:
            _LOG.error("unexpected error on execute NeonTx", exc_info=exc, extra=self._msg_filter)
            return ExecTxRespCode.Failed

        finally:
            self._destroy_alt_list(ctx)
            await self._op_client.free_resource(tx_request.req_id, is_good_resource, op_resource)

        return None

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_neon_tx(self, tx_request: ExecStuckTxRequest) -> ExecTxResp:
        with logging_context(**tx_request.req_id):
            for _ in itertools.count():
                if resp_code := await self._complete_stuck_neon_tx_impl(tx_request):
                    return ExecTxResp(code=resp_code)

    async def _complete_stuck_neon_tx_impl(self, tx_request: ExecStuckTxRequest) -> ExecTxRespCode | None:
        is_good_resource = True
        if (op_resource := tx_request.op_resource).is_empty:
            op_resource = await self._acquire_op_resource(tx_request)
        ctx = NeonExecTxCtx(self._server, op_resource, tx_request)

        try:
            return await self._neon_tx_executor.complete_stuck_neon_tx(ctx)

        except BadResourceError as exc:
            _LOG.warning("bad resource error: %s", str(exc))
            is_good_resource = False

        except BaseException as exc:
            _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)

        finally:
            self._destroy_alt_list(ctx)
            if tx_request.op_resource.is_empty:
                await self._op_client.free_resource(tx_request.req_id, is_good_resource, op_resource)

        return ExecTxRespCode.Failed

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

    async def _acquire_op_resource(self, tx_request: ExecTxRequest | ExecStuckTxRequest) -> OpResourceModel:
        for _ in itertools.count():
            op_resource = await self._op_client.get_resource(tx_request.req_id, tx_request.token.chain_id)
            if not op_resource.is_empty:
                return op_resource
            await asyncio.sleep(self._fail_sleep_sec)

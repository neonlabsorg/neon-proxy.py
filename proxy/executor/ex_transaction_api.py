from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager, contextmanager
from typing import ClassVar, Final, AsyncGenerator, Callable, Generator, Sequence

from common.config.constants import ONE_BLOCK_SEC, MIN_FINALIZE_SEC
from common.ethereum.hash import EthTxHash
from common.neon.transaction_model import NeonSkdTxModel
from common.neon_rpc.api import HolderAccountModel
from common.solana.alt_program import SolAltID
from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_property, ttl_cached_method
from common.utils.json_logger import logging_context
from .alt_destroyer import SolAltDestroyer
from .errors import StuckTxError
from .server_abc import ExecutorApi
from .skd_tree_parser import NeonSkdTreeParser
from .transaction_executor import NeonTxExecutor
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxDoneCode
from ..base.ex_api import (
    ExecTxRequest,
    ExecTxResp,
    CompleteStuckTxRequest,
    NeonAltModel,
    ExecTokenModel,
    CompleteStuckTxResp,
    DestroyTreeAccountRequest,
    DestroyTreeAccountResp,
)
from ..base.intl_server import BaseProxyApi
from ..base.mp_api import MpStuckTxModel, MpTxModel, MpGasPriceModel
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


class NeonTxExecApi(ExecutorApi):
    name: ClassVar[str] = "Executor::Transaction"
    _fail_sleep_sec: Final[float] = ONE_BLOCK_SEC / 4  # 4 times per block

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._task_dict: dict[EthTxHash, asyncio.Task] = dict()
        self._completed_task_list: list[asyncio.Task] = list()

    @BaseProxyApi.method(name="executeNeonTransaction")
    async def exec_neon_tx(self, request: ExecTxRequest) -> ExecTxResp:
        async def new_task() -> None:
            if request.tx.neon_tx.is_scheduled_tx:
                async with self._acquire_neon_skd_tree(request) as skd_tree_parser:
                    code = await self._exec_neon_skd_tree_retry_loop(skd_tree_parser, request)
            else:
                code = await self._exec_neon_tx_retry_loop(request, None)

            neon_acct = await self._core_api_client.get_neon_account(request.payer, None)
            await self._mp_client.done_exec_tx(request.neon_tx_hash, request.tx.nonce, code, neon_acct)

        result = await self._run_task(request, new_task)
        return ExecTxResp(result=result)

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_neon_tx(self, request: CompleteStuckTxRequest) -> CompleteStuckTxResp:
        async def new_task() -> None:
            code = await self._validate_stuck_neon_tx(request, None, None)
            await self._mp_client.done_complete_stuck_tx(request.neon_tx_hash, code)

        result = await self._run_task(request, new_task)
        return CompleteStuckTxResp(result=result)

    @BaseProxyApi.method(name="destroyTreeAccount")
    async def destroy_neon_skd_tree(self, request: DestroyTreeAccountRequest) -> DestroyTreeAccountResp:
        async def new_task() -> None:
            async with self._acquire_neon_skd_tree(request) as skd_tree_parser:
                stuck_tx = MpStuckTxModel.from_raw(request.neon_tx_hash, SolPubKey.default())
                stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)
                await self._destroy_tree_account(stuck_req, request.token, skd_tree_parser)

        result = await self._run_task(request, new_task)
        return DestroyTreeAccountResp(result=result)

    async def _exec_neon_tx_retry_loop(
        self,
        request: ExecTxRequest,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> ExecTxDoneCode:
        async def complete_stuck_neon_tx(stuck_req_: CompleteStuckTxRequest, op_res_: OpResourceModel) -> None:
            try:
                await self._validate_stuck_neon_tx(stuck_req_, op_res_, None)
            finally:
                await self._free_op_resource(stuck_req_.req_id, op_res_)

        alt_id_list: Sequence[SolAltID] = tuple()
        while True:
            op_res = await self._acquire_op_resource(request)
            with self._create_ctx(op_res, request, request.token, skd_tree_parser) as ctx:
                # if retry > 0:
                #     _LOG.debug("retry %d to execute NeonTx %s", retry, request.neon_tx_hash)

                try:
                    # reuse already created ALTs
                    ctx.add_alt_id(alt_id_list)
                    alt_id_list = tuple()

                    code = await self._neon_tx_executor.exec_neon_tx(ctx)
                    await self._free_op_resource(request.req_id, op_res)
                    return code

                except StuckTxError as exc:
                    _LOG.debug("switch to complete the stuck NeonTx %s", exc.neon_tx_hash)

                    stuck_tx = MpStuckTxModel.from_raw(exc.neon_tx_hash, exc.holder_address)
                    stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)
                    if not self._run_task(stuck_req, complete_stuck_neon_tx, stuck_req, op_res):
                        await self._free_op_resource(request.req_id, op_res)

                    _LOG.debug("return back to the execution of NeonTx %s", request.neon_tx_hash)
                    # reuse already created ALTs
                    alt_id_list = ctx.pop_alt_id_list()

                except BaseException as exc:
                    _LOG.error("unexpected error on execute NeonTx", exc_info=exc, extra=self._msg_filter)
                    await self._free_op_resource(request.req_id, op_res)
                    return ExecTxDoneCode.Failed

    async def _exec_neon_skd_tree_retry_loop(
        self,
        skd_tree_parser: NeonSkdTreeParser,
        skd_request: ExecTxRequest,
    ) -> ExecTxDoneCode:
        token = skd_request.token
        resp_code = ExecTxDoneCode.Failed

        async def exec_neon_tx(skd_tx_: NeonSkdTxModel) -> None:
            nonlocal resp_code

            mp_tx = MpTxModel.from_skd_tx(skd_tx_)
            request = ExecTxRequest(tx=mp_tx, token=token)

            with logging_context(**request.req_id):
                code = await self._exec_neon_tx_retry_loop(request, skd_tree_parser)
                if skd_tx_.neon_tx_hash == skd_request.neon_tx_hash:
                    resp_code = code

        async def complete_neon_tx(skd_tx_: NeonSkdTxModel) -> None:
            if not (holder_addr := await self._db.get_neon_skd_tx_holder_address(skd_tx_.neon_tx_hash)):
                # _LOG.debug("no holder for NeonSkdTx %s", _skd_tx.neon_tx_hash)
                return

            stuck_tx = MpStuckTxModel.from_raw(skd_tx_.neon_tx_hash, holder_addr)
            stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)

            await self._validate_stuck_neon_tx(stuck_req, None, skd_tree_parser)

        last_good_time = time.monotonic()
        while True:
            if await skd_tree_parser.can_be_destroyed():
                now = time.monotonic()
                if (now - last_good_time) > MIN_FINALIZE_SEC:
                    await self._destroy_tree_account(skd_request, skd_request.token, skd_tree_parser)
                    break
            elif not await skd_tree_parser.is_exist():
                break
            else:
                last_good_time = time.monotonic()

            # if retry > 0:
            #     _LOG.debug("retry %d to execute NeonSkdTx %s", retry, skd_tree_parser.neon_tx_hash)

            task_list: list[asyncio.Task] = list()
            async for status, skd_tx in skd_tree_parser.iter_active_neon_skd_tx_list():
                if not await skd_tree_parser.is_exist():
                    break
                elif status == status.InProgress:
                    if skd_tx.neon_tx_hash in self._task_dict:
                        continue
                    task = asyncio.create_task(complete_neon_tx(skd_tx))
                elif status == status.NotStarted:
                    task = asyncio.create_task(exec_neon_tx(skd_tx))
                else:
                    continue
                task_list.append(task)

            if task_list:
                await asyncio.gather(*task_list)

            await asyncio.sleep(self._fail_sleep_sec)

        return resp_code

    async def _validate_stuck_neon_tx(
        self,
        request: CompleteStuckTxRequest,
        op_resource: OpResourceModel | None,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> ExecTxDoneCode:
        try:
            holder_acct = await self._core_api_client.get_holder_account(request.stuck_tx.holder_address)
            if holder_acct.neon_tx_hash != request.neon_tx_hash:
                return ExecTxDoneCode.Failed

            if not op_resource:
                op_resource = await self._acquire_op_key(request.req_id, holder_acct.chain_id)

            if (not skd_tree_parser) and holder_acct.is_scheduled_tx:
                async with self._acquire_neon_skd_tree(holder_acct) as skd_tree_parser:
                    if not (await skd_tree_parser.is_exist()):
                        return ExecTxDoneCode.Failed
                    return await self._complete_stuck_neon_tx(request, op_resource, skd_tree_parser)

            return await self._complete_stuck_neon_tx(request, op_resource, skd_tree_parser)

        except BaseException as exc:
            _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)
            return ExecTxDoneCode.Failed

    async def _complete_stuck_neon_tx(
        self,
        request: CompleteStuckTxRequest,
        op_resource: OpResourceModel,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> ExecTxDoneCode:
        gas_price = await self._get_gas_price()
        token = gas_price.chain_dict.get(op_resource.chain_id)
        exec_token = ExecTokenModel.from_raw(token)

        with self._create_ctx(op_resource, request, exec_token, skd_tree_parser) as ctx:
            return await self._neon_tx_executor.complete_stuck_neon_tx(ctx)

    @cached_property
    def _neon_tx_executor(self) -> NeonTxExecutor:
        return self._server._neon_tx_executor  # noqa

    @cached_property
    def _sol_alt_destroyer(self) -> SolAltDestroyer:
        return self._server._sol_alt_destroyer  # noqa

    @asynccontextmanager
    async def _acquire_neon_skd_tree(
        self,
        request: ExecTxRequest | HolderAccountModel | DestroyTreeAccountRequest,
    ) -> AsyncGenerator[NeonSkdTreeParser, None]:
        skd_tree_parser = NeonSkdTreeParser(self._server, request.payer, request.nonce, request.neon_tx_hash)
        with logging_context(**skd_tree_parser.req_id):
            try:
                await skd_tree_parser.start()
                yield skd_tree_parser
            except BaseException as exc:
                _LOG.error("unexpected error on acquire NeonSkdTree", exc_info=exc, extra=self._msg_filter)
                raise
            finally:
                await skd_tree_parser.stop()

    @contextmanager
    def _create_ctx(
        self,
        op_resource: OpResourceModel,
        tx_request: ExecTxRequest | CompleteStuckTxRequest,
        token: ExecTokenModel | None,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> Generator[NeonExecTxCtx, None]:
        ctx = NeonExecTxCtx(self._server, op_resource, tx_request, token, skd_tree_parser)
        try:
            yield ctx
        finally:
            if not ctx.alt_id_list:
                return

            alt_list = tuple(map(lambda x: NeonAltModel(neon_tx_hash=ctx.neon_tx_hash, sol_alt_id=x), ctx.alt_id_list))
            self._sol_alt_destroyer.destroy_alt_list(alt_list)

    async def _acquire_op_resource(self, request: ExecTxRequest) -> OpResourceModel:
        # _LOG.debug("acquire holder for %s", request.neon_tx_hash)
        while True:
            try:
                op_res = await self._op_client.get_resource(request.req_id, request.token.chain_id)
                if not op_res.is_empty:
                    return op_res
            except BaseException as exc:
                _LOG.error("unexpected error on get resource", exc_info=exc, extra=self._msg_filter)
            await asyncio.sleep(self._fail_sleep_sec)

    async def _free_op_resource(self, req_id: dict, op_res: OpResourceModel) -> None:
        try:
            await self._op_client.free_resource(req_id, True, op_res)
        except BaseException as exc:
            _LOG.error("unexpected error on free resource", exc_info=exc, extra=self._msg_filter)

    async def _acquire_op_key(self, req_id: dict, chain_id) -> OpResourceModel:
        while True:
            try:
                op_res = await self._op_client.get_active_key(req_id, chain_id)
                if not op_res.is_empty:
                    return op_res
            except BaseException as exc:
                _LOG.error("unexpected error on get active key", exc_info=exc, extra=self._msg_filter)
            await asyncio.sleep(self._fail_sleep_sec)

    async def _run_task(
        self,
        request: ExecTxRequest | CompleteStuckTxRequest | DestroyTreeAccountRequest,
        func: Callable,
        *args,
    ) -> bool:
        # free memory of completed asyncio tasks
        task_list, self._completed_task_list = self._completed_task_list, list()
        if task_list:
            await asyncio.gather(*task_list)

        tx_hash = request.neon_tx_hash
        if tx_hash in self._task_dict:
            return False

        async def new_task() -> None:
            with logging_context(**request.req_id):
                try:
                    await func(*args)
                except BaseException as exc:
                    _LOG.error("unexpected error on run task", exc_info=exc, extra=self._msg_filter)
                finally:
                    if task := self._task_dict.pop(tx_hash, None):
                        self._completed_task_list.append(task)

        self._task_dict[tx_hash] = asyncio.create_task(new_task())
        return True

    async def _destroy_tree_account(
        self,
        request: ExecTxRequest | CompleteStuckTxRequest,
        token: ExecTokenModel,
        skd_tree_parser: NeonSkdTreeParser,
    ) -> None:
        op_res = await self._acquire_op_key(request.req_id, skd_tree_parser.chain_id)
        with self._create_ctx(op_res, request, token, skd_tree_parser) as ctx:
            await self._neon_tx_executor.destroy_tree_account(ctx)

    @ttl_cached_method(ttl_sec=10)
    async def _get_gas_price(self) -> MpGasPriceModel:
        return await self._mp_client.get_gas_price()

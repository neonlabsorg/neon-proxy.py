from __future__ import annotations

import asyncio
import itertools
import logging
import time
from typing import ClassVar, Final, Sequence

from common.config.constants import ONE_BLOCK_SEC, MIN_FINALIZE_SEC
from common.ethereum.hash import EthTxHash
from common.neon.neon_program import NeonEvmIxCode, NeonBaseTxAccountSet
from common.neon.transaction_model import NeonSkdTxModel
from common.solana.cb_program import SolCbProg
from common.solana.commit_level import SolCommit
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.transaction_legacy import SolLegacyTx
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
        await self._complete_task_list()

        tx_hash = request.tx.neon_tx_hash
        if tx_hash in self._task_dict:
            return ExecTxResp(result=False)

        async def _new_task() -> None:
            nonlocal tx_hash

            with logging_context(**request.req_id):
                if request.tx.neon_tx.is_scheduled_tx:
                    code = await self._exec_neon_skd_tree(request)
                else:
                    code = await self._exec_neon_tx_retry_loop(request, None)

                neon_acct = await self._core_api_client.get_neon_account(request.sender, None)
                await self._mp_client.done_exec_tx(tx_hash, code, neon_acct)

            if task := self._task_dict.pop(tx_hash, None):
                self._completed_task_list.append(task)

        self._task_dict[tx_hash] = asyncio.create_task(_new_task())
        return ExecTxResp(result=True)

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_neon_tx(self, request: CompleteStuckTxRequest) -> CompleteStuckTxResp:
        await self._complete_task_list()

        tx_hash = request.stuck_tx.neon_tx_hash
        if tx_hash in self._task_dict:
            return CompleteStuckTxResp(result=False)

        async def _new_task() -> None:
            nonlocal tx_hash
            with logging_context(**request.req_id):
                code = await self._complete_stuck_neon_tx_retry_loop(request, None)
                await self._mp_client.done_complete_stuck_tx(tx_hash, code)

            if task := self._task_dict.pop(tx_hash, None):
                self._completed_task_list.append(task)

        self._task_dict[tx_hash] = asyncio.create_task(_new_task())
        return CompleteStuckTxResp(result=True)

    @BaseProxyApi.method(name="destroyTreeAccount")
    async def destroy_neon_skd_tree(self, request: DestroyTreeAccountRequest) -> DestroyTreeAccountResp:
        tx_hash = request.neon_tx_hash
        if tx_hash in self._task_dict:
            return DestroyTreeAccountResp(result=False)

        async def _new_task() -> None:
            with logging_context(**request.req_id):
                skd_tree_parser = NeonSkdTreeParser(self._server, request.payer, request.nonce)
                try:
                    await skd_tree_parser.start()
                    await self._destroy_tree_account(skd_tree_parser)
                finally:
                    await skd_tree_parser.stop()

                if task := self._task_dict.pop(tx_hash, None):
                    self._completed_task_list.append(task)

        self._task_dict[tx_hash] = asyncio.create_task(_new_task())
        return DestroyTreeAccountResp(result=True)

    async def _exec_neon_tx_retry_loop(
        self,
        request: ExecTxRequest,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> ExecTxDoneCode:

        async def _free_res(req_id: dict, _op_res: OpResourceModel | None, _ctx: NeonExecTxCtx | None) -> None:
            if _ctx:
                self._destroy_alt_list(_ctx)
            if _op_res:
                await self._op_client.free_resource(req_id, True, _op_res)

        async def _complete_stuck_neon_tx(_op_res: OpResourceModel, _ctx: NeonExecTxCtx, _exc: StuckTxError) -> None:
            stuck_tx = MpStuckTxModel.from_raw(_exc.neon_tx_hash, _exc.holder_address)

            stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)
            with logging_context(**stuck_req.req_id):
                await self._complete_stuck_neon_tx_retry_loop(stuck_req, None)
                await _free_res(stuck_req.req_id, _op_res, _ctx)

            if _task := self._task_dict.pop(_exc.neon_tx_hash, None):
                self._completed_task_list.append(_task)

        for _retry in itertools.count():
            op_res = await self._acquire_op_resource(request)
            ctx = NeonExecTxCtx(self._server, op_res, request, request.token, skd_tree_parser)

            # if retry > 0:
            #     _LOG.debug("retry %d to execute NeonTx %s", retry, request.tx.neon_tx_hash)

            try:
                return await self._neon_tx_executor.exec_neon_tx(ctx)

            except StuckTxError as exc:
                if exc.neon_tx_hash not in self._task_dict:
                    _LOG.debug("switch to complete the stuck NeonTx %s", exc.neon_tx_hash)
                    task = asyncio.create_task(_complete_stuck_neon_tx(op_res, ctx, exc))
                    self._task_dict[exc.neon_tx_hash] = task

                    op_res, ctx = None, None
                    _LOG.debug("return back to the execution of NeonTx %s", request.tx.neon_tx_hash)

            except BaseException as exc:
                _LOG.error("unexpected error on execute NeonTx", exc_info=exc, extra=self._msg_filter)
                return ExecTxDoneCode.Failed

            finally:
                await _free_res(request.req_id, op_res, ctx)

    async def _exec_neon_skd_tree(self, request: ExecTxRequest) -> ExecTxDoneCode:
        tx = request.tx
        skd_tree_parser = NeonSkdTreeParser(self._server, request.sender, tx.nonce)
        try:
            await skd_tree_parser.start()
            resp_code = await self._exec_neon_skd_tree_retry_loop(skd_tree_parser, request.token)
            return resp_code
        finally:
            await skd_tree_parser.stop()

    async def _exec_neon_skd_tree_retry_loop(
        self,
        skd_tree_parser: NeonSkdTreeParser,
        token: ExecTokenModel,
    ) -> ExecTxDoneCode:
        resp_code = ExecTxDoneCode.Failed

        async def _exec_neon_tx(_skd_tx: NeonSkdTxModel) -> None:
            nonlocal skd_tree_parser
            nonlocal token
            nonlocal resp_code

            mp_tx = MpTxModel.from_skd_tx(_skd_tx)
            request = ExecTxRequest(tx=mp_tx, token=token)

            with logging_context(**request.req_id, skd_tree=_skd_tx.tree_address.ident):
                _resp_code = await self._exec_neon_tx_retry_loop(request, skd_tree_parser)
                if _skd_tx.neon_tx_hash == skd_tree_parser.neon_tx_hash:
                    resp_code = _resp_code

        async def _complete_neon_tx(_skd_tx: NeonSkdTxModel) -> None:
            nonlocal token

            with logging_context(tx=_skd_tx.neon_tx_hash.ident, skd_tree=_skd_tx.tree_address.ident):
                if not (holder_addr := await self._db.get_neon_skd_tx_holder_address(_skd_tx.neon_tx_hash)):
                    # _LOG.debug("no holder for NeonSkdTx %s", _skd_tx.neon_tx_hash)
                    return

                stuck_tx = MpStuckTxModel.from_raw(_skd_tx.neon_tx_hash, holder_addr)
                stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)

                await self._complete_stuck_neon_tx_retry_loop(stuck_req, skd_tree_parser)

        last_good_time = time.monotonic()
        for _retry in itertools.count():
            if await skd_tree_parser.can_be_destroyed():
                now = time.monotonic()
                if (now - last_good_time) > MIN_FINALIZE_SEC:
                    await self._destroy_tree_account(skd_tree_parser)
                    break
            else:
                last_good_time = time.monotonic()

            # if retry > 0:
            #     _LOG.debug("retry %d to execute NeonSkdTx %s", retry, skd_tree_parser.neon_tx_hash)

            task_list: list[asyncio.Task] = list()
            async for status, skd_tx in skd_tree_parser.iter_neon_skd_tx_list():
                if status == status.InProgress:
                    task = asyncio.create_task(_complete_neon_tx(skd_tx))
                elif status == status.NotStarted:
                    task = asyncio.create_task(_exec_neon_tx(skd_tx))
                else:
                    continue
                task_list.append(task)

            if task_list:
                await asyncio.gather(*task_list)

            await asyncio.sleep(self._fail_sleep_sec)

        return resp_code

    async def _complete_stuck_neon_tx_retry_loop(
        self,
        request: CompleteStuckTxRequest,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> ExecTxDoneCode:
        holder_acct = await self._core_api_client.get_holder_account(request.stuck_tx.holder_address)
        if holder_acct.neon_tx_hash != request.stuck_tx.neon_tx_hash:
            return ExecTxDoneCode.Failed

        is_new_skd_tree_parser = False
        if (not skd_tree_parser) and holder_acct.is_scheduled_tx:
            is_new_skd_tree_parser = True
            skd_tree_parser = NeonSkdTreeParser(self._server, holder_acct.payer, holder_acct.tx.nonce)
            if not (await skd_tree_parser.is_exist()):
                return ExecTxDoneCode.Failed

        gas_price = await self._get_gas_price()
        token = gas_price.chain_dict.get(holder_acct.chain_id)
        exec_token = ExecTokenModel.from_raw(gas_price, token)
        op_res = await self._acquire_op_key(request.req_id, holder_acct.chain_id)
        ctx = NeonExecTxCtx(self._server, op_res, request, exec_token, skd_tree_parser)

        try:
            for _retry in itertools.count():
                # if retry > 0:
                #     _LOG.debug("retry %d to complete stuck NeonTx %s", retry, request.tx.neon_tx_hash)

                try:
                    return await self._neon_tx_executor.complete_stuck_neon_tx(ctx)

                except BaseException as exc:
                    _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)
                    return ExecTxDoneCode.Failed
        finally:
            self._destroy_alt_list(ctx)
            if is_new_skd_tree_parser:
                await skd_tree_parser.stop()

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

    async def _acquire_op_resource(self, request: ExecTxRequest) -> OpResourceModel:
        _LOG.debug("acquire holder for %s", request.tx.neon_tx_hash)
        for _ in itertools.count():
            op_res = await self._op_client.get_resource(request.req_id, request.token.chain_id)
            if not op_res.is_empty:
                return op_res
            await asyncio.sleep(self._fail_sleep_sec)

    async def _acquire_op_key(self, req_id: dict, chain_id) -> OpResourceModel:
        for _ in itertools.count():
            op_res = await self._op_client.get_active_key(req_id, chain_id)
            if not op_res.is_empty:
                return op_res
            await asyncio.sleep(self._fail_sleep_sec)

    async def _complete_task_list(self) -> None:
        task_list, self._completed_task_list = self._completed_task_list, list()
        if task_list:
            await asyncio.gather(*task_list)

    async def _destroy_tree_account(self, skd_tree_parser: NeonSkdTreeParser) -> None:
        try:
            stuck_tx = MpStuckTxModel.from_raw(skd_tree_parser.neon_tx_hash, SolPubKey.default())
            stuck_req = CompleteStuckTxRequest(stuck_tx=stuck_tx)
            op_res = await self._acquire_op_key(stuck_req.req_id, skd_tree_parser.chain_id)
            payer_acct = await self._core_api_client.get_neon_account(skd_tree_parser.payer, None)

            ctx = NeonExecTxCtx(self._server, op_res, stuck_req, None, skd_tree_parser)

            base_tx_acct_set = NeonBaseTxAccountSet(
                payer=payer_acct.sol_address,
                sender=payer_acct.sol_address,
                receiver=SolPubKey.default(),
                receiver_contract=SolPubKey.default(),
                payer_balance=payer_acct.balance,
            )
            ctx.set_tx_sol_address(base_tx_acct_set)

            for _ in itertools.count():
                await self._destroy_tree_account_retry_loop(ctx)
                await asyncio.sleep(1)

                acct = await self._sol_client.get_account(skd_tree_parser.address, 1, SolCommit.Finalized)
                if acct.is_empty:
                    await self._db.destroy_tree_account(skd_tree_parser.address)
                    break

        except BaseException as exc:
            _LOG.error("error on destroy tree account: %s", str(exc))

    async def _destroy_tree_account_retry_loop(self, ctx: NeonExecTxCtx) -> None:
        if not (await ctx.skd_tree_parser.is_exist()):
            return

        name = NeonEvmIxCode.SkdTreeDestroy.name
        destroy_ix = ctx.neon_prog.make_destroy_skd_tree_ix()

        cu_price_ix = SolCbProg.make_cu_price_ix(self._cfg.def_simple_cu_price)
        cu_limit_ix = SolCbProg.make_cu_limit_ix(ctx.neon_prog.CuLimitSkdTreeAccountDestroy)
        ix_list: Sequence[SolTxIx] = tuple([cu_price_ix, cu_limit_ix, destroy_ix])

        tx_list_sender = ctx.sol_tx_list_sender

        for _ in itertools.count():
            if not (await ctx.skd_tree_parser.is_exist()):
                return
            elif not (await ctx.skd_tree_parser.can_be_destroyed()):
                return

            tx = SolLegacyTx(name=name, ix_list=ix_list)
            await tx_list_sender.send([tx])

    @ttl_cached_method(ttl_sec=10)
    async def _get_gas_price(self) -> MpGasPriceModel:
        return await self._mp_client.get_gas_price()

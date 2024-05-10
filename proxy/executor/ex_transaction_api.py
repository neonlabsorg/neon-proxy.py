from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EmulNeonCallModel, HolderAccountStatus
from common.solana.errors import SolTxSizeError, SolError
from common.solana.pubkey import SolPubKey
from common.solana_rpc.errors import (
    SolCbExceededError,
    SolNeonRequireResizeIterError,
    SolUnknownReceiptError,
    SolNoMoreRetriesError,
    SolBlockhashNotFound,
)
from common.utils.json_logger import logging_context
from .errors import BadResourceError, StuckTxError, TxAccountCntTooHighError, WrongStrategyError
from .server_abc import ExecutorApi
from .strategy_base import BaseTxStrategy
from .strategy_iterative import IterativeTxStrategy, AltIterativeTxStrategy
from .strategy_iterative_holder import HolderTxStrategy, AltHolderTxStrategy
from .strategy_iterative_no_chain_id import NoChainIdTxStrategy, AltNoChainIdTxStrategy
from .strategy_simple import SimpleTxStrategy, AltSimpleTxStrategy
from .strategy_simple_holder import SimpleHolderTxStrategy, AltSimpleHolderTxStrategy
from .strategy_simple_solana_call import SimpleTxSolanaCallStrategy, AltSimpleTxSolanaCallStrategy
from .strategy_simple_solana_call_holder import SimpleHolderTxSolanaCallStrategy, AltSimpleHolderTxSolanaCallStrategy
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxRequest, ExecTxResp, ExecTxRespCode, ExecStuckTxRequest
from ..base.mp_api import MpStuckTxModel
from ..base.server import BaseProxyApi

_LOG = logging.getLogger(__name__)


class NeonTxExecApi(ExecutorApi):
    name: ClassVar[str] = "Executor::Transaction"

    _tx_strategy_list = [
        # single iteration
        SimpleTxStrategy,
        #     + alt
        AltSimpleTxStrategy,
        #     + holder
        SimpleHolderTxStrategy,
        #     + alt + holder
        AltSimpleHolderTxStrategy,
        # multi-iteration
        IterativeTxStrategy,
        #     + alt
        AltIterativeTxStrategy,
        #     + holder
        HolderTxStrategy,
        #     + alt + holder
        AltHolderTxStrategy,
        # without-chain-id
        #     + holder
        NoChainIdTxStrategy,
        #     + alt + holder
        AltNoChainIdTxStrategy,
        # single iteration with Solana Call
        SimpleTxSolanaCallStrategy,
        #     + alt
        AltSimpleTxSolanaCallStrategy,
        #     + holder
        SimpleHolderTxSolanaCallStrategy,
        #     + alt + holder
        AltSimpleHolderTxSolanaCallStrategy,
    ]

    _stuck_tx_strategy_list = [
        # multi-iteration
        #     + holder
        HolderTxStrategy,
        #     + alt + holder
        AltHolderTxStrategy,
    ]

    @BaseProxyApi.method(name="executeNeonTransaction")
    async def exec_tx(self, tx_request: ExecTxRequest) -> ExecTxResp:
        tx = tx_request.tx
        with logging_context(tx=tx.tx_id):
            ctx = NeonExecTxCtx(self._server, tx_request)
            while True:  # for case when holder has a stuck NeonTx
                try:
                    exit_code = await self._exec_neon_tx(ctx, self._tx_strategy_list)
                    state_tx_cnt = await self._get_state_tx_cnt(ctx)
                    return ExecTxResp(code=exit_code, state_tx_cnt=state_tx_cnt)

                except StuckTxError as exc:
                    _LOG.debug("switch to complete the stuck NeonTx %s", exc.neon_tx_hash)
                    # reset token_address, because the tx can be in another chain-id space
                    resource = tx_request.resource.model_copy(update=dict(token_sol_address=SolPubKey.default()))
                    stuck_tx = MpStuckTxModel.from_raw(exc.neon_tx_hash, exc.address)
                    req = ExecStuckTxRequest(stuck_tx=stuck_tx, resource=resource)
                    await self.complete_stuck_tx(req)

                    _LOG.debug("return back to execute NeonTx %s", tx.neon_tx_hash)

                except BaseException as exc:
                    _LOG.error("unexpected error on execute NeonTx", exc_info=exc, extra=self._msg_filter)

    @BaseProxyApi.method(name="completeStuckNeonTransaction")
    async def complete_stuck_tx(self, tx_request: ExecStuckTxRequest) -> ExecTxResp:
        tx = tx_request.stuck_tx
        with logging_context(tx=tx.tx_id):
            try:
                holder = await self._core_api_client.get_holder_account(tx.holder_address)
                if holder.status != HolderAccountStatus.Active or holder.neon_tx_hash != tx.neon_tx_hash:
                    _LOG.debug("holder %s doesn't have NeonTx %s", tx.holder_address, tx.neon_tx_hash)
                    return ExecTxResp(code=ExecTxRespCode.Failed)

                # get the chain-id from the holder
                chain_id = holder.chain_id
                payer = tx_request.resource.owner

                # request the token address (based on chain-id) for receiving payments from user
                token_sol_addr = await self._op_client.get_token_sol_address(tx.tx_id, payer, chain_id)

                ctx = NeonExecTxCtx(self._server, tx_request, chain_id=chain_id)
                ctx.set_token_sol_address(token_sol_addr)
                ctx.set_holder_account(holder)

                # update NeonProg settings from EVM config
                await ctx.get_evm_cfg()

                exit_code = await self._exec_neon_tx(ctx, self._stuck_tx_strategy_list)
                return ExecTxResp(code=exit_code)

            except BaseException as exc:
                _LOG.error("unexpected error on complete stuck NeonTx", exc_info=exc, extra=self._msg_filter)
                return ExecTxResp(code=ExecTxRespCode.Done)

    async def _exec_neon_tx(self, ctx: NeonExecTxCtx, tx_strategy_list: list[type[BaseTxStrategy]]) -> ExecTxRespCode:
        if ctx.is_stuck_tx:
            has_emul_result = False
        else:
            await self._validate_nonce(ctx)
            await self._emulate_neon_tx(ctx)
            has_emul_result = True  # to avoid double emulation at the first attempt

        for _Strategy in tx_strategy_list:
            strategy = _Strategy(ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.name, strategy.validation_error_msg)
                continue

            _LOG.debug("use strategy %s", strategy.name)
            if (exit_code := await self._exec_strategy(ctx, strategy, has_emul_result)) is not None:
                _LOG.debug("got result %s from strategy %s", exit_code.name, strategy.name)
                return exit_code
            has_emul_result = False

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxRespCode.Failed

    async def _exec_strategy(
        self, ctx: NeonExecTxCtx, strategy: BaseTxStrategy, has_emul_result: bool
    ) -> ExecTxRespCode | None:
        for retry in itertools.count():
            if retry > 0:
                _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                has_changes = await strategy.prep_before_emulate()
                if has_changes or (not has_emul_result):
                    has_emul_result = False  # to avoid double emulation at the first attempt
                    if not ctx.is_stuck_tx:
                        await self._emulate_neon_tx(ctx)
                        await self._validate_nonce(ctx)
                    await strategy.update_after_emulate()

                # Preparations made changes in the Solana state -> repeat the preparation and emulation
                if has_changes:
                    continue

                # NeonTx is prepared for the execution
                try:
                    return await strategy.execute()
                finally:
                    if strategy.has_good_sol_tx_receipt:
                        ctx.mark_good_sol_tx_receipt()

            except (BadResourceError, StuckTxError, TxAccountCntTooHighError) as exc:
                _LOG.warning("bad resource error: %s", str(exc))
                if isinstance(exc, StuckTxError):
                    raise
                return ExecTxRespCode.BadResource

            except (WrongStrategyError, SolCbExceededError, SolNeonRequireResizeIterError, SolTxSizeError) as exc:
                _LOG.debug("wrong strategy error: %s", str(exc))
                return None

            except (EthError, SolUnknownReceiptError) as exc:
                _LOG.debug("execution error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(strategy)

            except SolError as exc:
                _LOG.debug("simple error, let's repeat the attempt: %s", str(exc), extra=self._msg_filter)
                await asyncio.sleep(ONE_BLOCK_SEC / 2)

            except BaseException as exc:
                _LOG.debug("unexpected error", extra=self._msg_filter, exc_info=exc)
                return await self._cancel_neon_tx(strategy)

    async def _cancel_neon_tx(self, strategy: BaseTxStrategy) -> ExecTxRespCode | None:
        for retry in itertools.count():
            if retry > 0:
                _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel()

            except (SolNoMoreRetriesError, SolBlockhashNotFound):
                await asyncio.sleep(ONE_BLOCK_SEC)

            except BaseException as exc:
                _LOG.error("unexpected error on cancel NeonTx", exc_info=exc, extra=self._msg_filter)
                return None

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx) -> None:
        evm_cfg = await ctx.get_evm_cfg()

        resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            EmulNeonCallModel.from_neon_tx(ctx.neon_tx, ctx.chain_id),
            check_result=False,
        )
        acct_meta_cnt = NeonProg.BaseAccountCnt + len(resp.raw_meta_list)
        if acct_meta_cnt > self._cfg.max_tx_account_cnt:
            if not ctx.has_good_sol_tx_receipt:
                raise TxAccountCntTooHighError(acct_meta_cnt, self._cfg.max_tx_account_cnt)
            # it's a bad idea to block the tx execution by additional accounts in Solana txs
            #  so don't change the list of accounts if there is a good receipt
        else:
            ctx.set_emulator_result(resp)

    async def _validate_nonce(self, ctx: NeonExecTxCtx) -> None:
        if ctx.has_good_sol_tx_receipt:
            return

        state_tx_cnt = await self._get_state_tx_cnt(ctx)
        EthNonceTooHighError.raise_if_error(ctx.neon_tx.nonce, state_tx_cnt)
        EthNonceTooLowError.raise_if_error(ctx.neon_tx.nonce, state_tx_cnt)

    async def _get_state_tx_cnt(self, ctx: NeonExecTxCtx) -> int:
        return await self._core_api_client.get_state_tx_cnt(ctx.sender, None)

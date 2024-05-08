from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.neon_program import NeonProg
from common.solana.errors import SolTxSizeError, SolError
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
        # without-chain-id
        #     + holder
        NoChainIdTxStrategy,
        #     + alt + holder
        AltNoChainIdTxStrategy,
    ]

    @BaseProxyApi.method(name="executeTransaction")
    async def exec_tx(self, tx_request: ExecTxRequest) -> ExecTxResp:
        with logging_context(tx=tx_request.tx.tx_id):
            ctx = NeonExecTxCtx(self._cfg, self._sol_client, self._core_api_client, self._op_client, tx_request)
            exit_code = await self._execute_tx(ctx)
            state_tx_cnt = await self._get_state_tx_cnt(ctx)
            return ExecTxResp(code=exit_code, state_tx_cnt=state_tx_cnt)

    @BaseProxyApi.method(name="executeStuckTransaction")
    async def exec_stuck_tx(self, request: ExecStuckTxRequest) -> ExecTxResp:
        return ExecTxResp(code=ExecTxRespCode.Done)

    async def _execute_tx(self, ctx: NeonExecTxCtx) -> ExecTxRespCode:
        await self._validate_nonce(ctx)
        await self._emulate_neon_tx(ctx)

        for _Strategy in self._tx_strategy_list:
            strategy = _Strategy(ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.name, strategy.validation_error_msg)
                continue

            _LOG.debug("Use strategy %s", strategy.name)
            if (exit_code := await self._execute_strategy(ctx, strategy)) is not None:
                return exit_code

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxRespCode.Failed

    async def _execute_strategy(self, ctx: NeonExecTxCtx, strategy: BaseTxStrategy) -> ExecTxRespCode | None:
        for retry in itertools.count():
            if retry > 0:
                _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                has_changes = await strategy.prep_before_emulate()
                if has_changes or (retry == 0):
                    if not ctx.is_stuck_tx:
                        await self._emulate_neon_tx(ctx)
                        await self._validate_nonce(ctx)
                    await strategy.update_after_emulate()

                # Preparation made changes in the Solana state -> repeat preparation and emulation
                if has_changes:
                    continue

                # Neon tx is prepared for the execution
                try:
                    return await strategy.execute()
                finally:
                    if strategy.has_good_sol_tx_receipt:
                        ctx.mark_good_sol_tx_receipt()

            except (BadResourceError, StuckTxError, TxAccountCntTooHighError) as exc:
                _LOG.warning("bad resource error: %s", str(exc))
                return ExecTxRespCode.BadResource

            except (WrongStrategyError, SolCbExceededError, SolNeonRequireResizeIterError, SolTxSizeError) as exc:
                _LOG.debug("wrong strategy error: %s", str(exc))
                return None

            except (EthError, SolUnknownReceiptError) as exc:
                _LOG.debug("execution error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_tx(strategy)

            except SolError as exc:
                _LOG.debug("simple error, let's repeat attempt: %s", str(exc), extra=self._msg_filter)

            except BaseException as exc:
                _LOG.debug("unexpected error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_tx(strategy)

    async def _cancel_tx(self, strategy: BaseTxStrategy) -> ExecTxRespCode | None:
        for retry in itertools.count():
            _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel()

            except (SolNoMoreRetriesError, SolBlockhashNotFound):
                await asyncio.sleep(ONE_BLOCK_SEC)

            except BaseException as exc:
                _LOG.error("unexpected error on cancel tx", exc_info=exc, extra=self._msg_filter)
                return None

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx) -> None:
        evm_cfg = await self._server.get_evm_cfg()
        resp = await self._core_api_client.emulate_tx(
            evm_cfg,
            ctx.neon_tx,
            ctx.chain_id,
            preload_sol_address_list=ctx.account_key_list,
            sol_account_dict=dict(),
            check_result=False,
            block=None,
        )
        acct_meta_cnt = NeonProg.BaseAccountCnt + len(resp.raw_meta_list)
        if acct_meta_cnt > self._cfg.max_tx_account_cnt:
            if not ctx.has_good_sol_tx_receipt:
                raise TxAccountCntTooHighError(acct_meta_cnt, self._cfg.max_tx_account_cnt)
            # it's a bad idea to block the tx execution by additional accounts in a Solana txs
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

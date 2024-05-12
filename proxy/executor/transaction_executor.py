from __future__ import annotations

import asyncio
import itertools
import logging

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EmulNeonCallModel, HolderAccountStatus
from common.solana.errors import SolTxSizeError, SolError
from common.solana_rpc.errors import (
    SolCbExceededError,
    SolNeonRequireResizeIterError,
    SolUnknownReceiptError,
    SolNoMoreRetriesError,
    SolBlockhashNotFound,
)
from .errors import BadResourceError, StuckTxError, TxAccountCntTooHighError, WrongStrategyError
from .server_abc import ExecutorComponent
from .strategy_base import BaseTxStrategy
from .strategy_iterative import IterativeTxStrategy, AltIterativeTxStrategy
from .strategy_iterative_holder import HolderTxStrategy, AltHolderTxStrategy
from .strategy_iterative_no_chain_id import NoChainIdTxStrategy, AltNoChainIdTxStrategy
from .strategy_simple import SimpleTxStrategy, AltSimpleTxStrategy
from .strategy_simple_holder import SimpleHolderTxStrategy, AltSimpleHolderTxStrategy
from .strategy_simple_solana_call import SimpleTxSolanaCallStrategy, AltSimpleTxSolanaCallStrategy
from .strategy_simple_solana_call_holder import SimpleHolderTxSolanaCallStrategy, AltSimpleHolderTxSolanaCallStrategy
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxResp, ExecTxRespCode

_LOG = logging.getLogger(__name__)


class NeonTxExecutor(ExecutorComponent):
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

    async def exec_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxResp:
        holder = await self._core_api_client.get_holder_account(ctx.holder_address)
        if holder.status == HolderAccountStatus.Active and holder.neon_tx_hash != ctx.neon_tx_hash:
            _LOG.debug("holder %s contains stuck NeonTx %s", ctx.holder_address, ctx.neon_tx_hash)
            raise StuckTxError(holder)

        try:
            # the earlier check of the nonce
            await self._validate_nonce(ctx)
            # get the list of accounts for validation
            await self._emulate_neon_tx(ctx)

            has_emul_result = True  # to avoid the double emulation at the first run
            exit_code = await self._select_strategy(ctx, self._tx_strategy_list, has_emul_result)
            state_tx_cnt = await self._get_state_tx_cnt(ctx)

        except EthNonceTooLowError as exc:
            _LOG.debug("%s", str(exc))
            exit_code = ExecTxRespCode.NonceTooLow
            state_tx_cnt = exc.state_tx_cnt

        except EthNonceTooHighError as exc:
            _LOG.debug("%s", str(exc))
            exit_code = ExecTxRespCode.NonceTooHigh
            state_tx_cnt = exc.state_tx_cnt

        except TxAccountCntTooHighError as exc:
            _LOG.debug("%s", str(exc))
            exit_code = ExecTxRespCode.Failed
            state_tx_cnt = await self._get_state_tx_cnt(ctx)

        return ExecTxResp(code=exit_code, state_tx_cnt=state_tx_cnt)

    async def complete_stuck_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxResp:
        holder = await self._core_api_client.get_holder_account(ctx.holder_address)
        if holder.status != HolderAccountStatus.Active or holder.neon_tx_hash != ctx.neon_tx_hash:
            _LOG.debug("holder %s doesn't contain NeonTx %s", ctx.holder_address, ctx.neon_tx_hash)
            return ExecTxResp(code=ExecTxRespCode.Failed)

        ctx.set_chain_id(holder.chain_id)

        # request the token address (based on chain-id) for receiving payments from user
        token_sol_addr = await self._op_client.get_token_sol_address(ctx.req_id, ctx.payer, ctx.chain_id)
        ctx.set_token_sol_address(token_sol_addr)
        ctx.set_holder_account(holder)

        # update NeonProg settings from EVM config
        evm_cfg = await self._server.get_evm_cfg()
        ctx.init_neon_prog(evm_cfg)

        exit_code = await self._select_strategy(ctx, self._stuck_tx_strategy_list, True)
        return ExecTxResp(code=exit_code)

    async def _select_strategy(
        self,
        ctx: NeonExecTxCtx,
        tx_strategy_list: list[type[BaseTxStrategy]],
        has_emul_result: bool,
    ) -> ExecTxRespCode:
        for _Strategy in tx_strategy_list:
            strategy = _Strategy(ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.name, strategy.validation_error_msg)
                continue

            _LOG.debug("use strategy %s", strategy.name)
            if (exit_code := await self._exec_neon_tx(ctx, strategy, has_emul_result)) is not None:
                _LOG.debug("done strategy %s with result %s", strategy.name, exit_code.name)
                return exit_code
            has_emul_result = False

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxRespCode.Failed

    async def _exec_neon_tx(
        self,
        ctx: NeonExecTxCtx,
        strategy: BaseTxStrategy,
        has_emul_result: bool,
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

            except (EthNonceTooLowError, EthNonceTooHighError):
                raise

            except StuckTxError as exc:
                _LOG.warning("stuck NeonTx error: %s", str(exc))
                raise

            except BadResourceError as exc:
                _LOG.warning("bad resource error: %s", str(exc))
                return ExecTxRespCode.BadResource

            except (WrongStrategyError, SolCbExceededError, SolNeonRequireResizeIterError, SolTxSizeError) as exc:
                _LOG.debug("wrong strategy error: %s", str(exc))
                return None

            except (EthError, SolUnknownReceiptError, TxAccountCntTooHighError) as exc:
                _LOG.debug("execution error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(strategy)

            except SolError as exc:
                _LOG.debug("simple error: %s", str(exc), extra=self._msg_filter)
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
        # update evm config
        evm_cfg = await self._server.get_evm_cfg()
        ctx.init_neon_prog(evm_cfg)

        resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            EmulNeonCallModel.from_neon_tx(ctx.neon_tx, ctx.chain_id),
            preload_sol_address_list=ctx.account_key_list,
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
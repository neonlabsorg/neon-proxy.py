from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar, Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.neon_program import NeonBaseTxAccountSet
from common.solana.alt_program import SolAltAccountInfo
from common.solana.errors import SolTxSizeError, SolError
from common.solana_rpc.errors import (
    SolCbExceededError,
    SolNeonRequireResizeIterError,
    SolUnknownReceiptError,
    SolNoMoreRetriesError,
    SolBlockhashNotFound,
    SolCbExceededCriticalError,
    SolOutOfMemoryError,
)
from .errors import StuckTxError, WrongStrategyError, SkdTxError
from .server_abc import ExecutorComponent
from .strategy_base import BaseTxStrategy
from .strategy_iterative import IterativeTxStrategy, AltIterativeTxStrategy
from .strategy_iterative_holder import HolderTxStrategy, AltHolderTxStrategy
from .strategy_iterative_no_chain_id import NoChainIdTxStrategy, AltNoChainIdTxStrategy
from .strategy_iterative_solana_call_holder import HolderTxSolanaCallStrategy, AltHolderTxSolanaCallStrategy
from .strategy_simple import SimpleTxStrategy, AltSimpleTxStrategy
from .strategy_simple_holder import SimpleHolderTxStrategy, AltSimpleHolderTxStrategy
from .strategy_simple_solana_call import SimpleTxSolanaCallStrategy, AltSimpleTxSolanaCallStrategy
from .strategy_simple_solana_call_holder import SimpleHolderTxSolanaCallStrategy, AltSimpleHolderTxSolanaCallStrategy
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)
_BaseTxStrategyList = list[type[BaseTxStrategy]]


class NeonTxExecutor(ExecutorComponent):
    _wait_sec: Final[float] = max(ONE_BLOCK_SEC / 5, 0.005)

    _tx_strategy_list: ClassVar[_BaseTxStrategyList] = [
        # single iteration
        SimpleTxStrategy,
        #     + holder
        SimpleHolderTxStrategy,
        # multi-iteration
        IterativeTxStrategy,
        #     + holder
        HolderTxStrategy,
        # wo-chain-id
        #     + multi-iteration
        #     + holder
        NoChainIdTxStrategy,
        # ALT strategies:
        #     simple + alt
        AltSimpleTxStrategy,
        #     simple + alt + holder
        AltSimpleHolderTxStrategy,
        #     multi-iterative + alt
        AltIterativeTxStrategy,
        #     multi-iterative + alt + holder
        AltHolderTxStrategy,
        #     multi-iterative + wo-chain-id + alt + holder
        AltNoChainIdTxStrategy,
        # single iteration with Solana Call
        AltSimpleTxSolanaCallStrategy,
        #     + holder
        SimpleTxSolanaCallStrategy,
        #     + alt
        SimpleHolderTxSolanaCallStrategy,
        #     + alt + holder
        AltSimpleHolderTxSolanaCallStrategy,
        # multi-iteration with Solana call
        #     + holder
        HolderTxSolanaCallStrategy,
        #     + alt + holder
        AltHolderTxSolanaCallStrategy,
    ]

    _stuck_tx_strategy_list: ClassVar[_BaseTxStrategyList] = [
        # multi-iteration
        #     + holder
        HolderTxStrategy,
        #     + alt + holder
        AltHolderTxStrategy,
    ]

    async def exec_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxDoneCode:
        await ctx.holder_validator.validate_stuck_tx()

        try:
            await self._init_base_sol_tx(ctx)
            # get the list of accounts for validation
            await self._emulate_neon_tx(ctx)

            return await self._select_strategy(ctx, self._tx_strategy_list)

        except SkdTxError as _exc:
            # _LOG.debug("%s", str(exc))
            return ExecTxDoneCode.Failed

        except EthNonceTooLowError as _exc:
            # _LOG.debug("%s", str(exc))
            return ExecTxDoneCode.NonceTooLow

        except EthNonceTooHighError as _exc:
            # _LOG.debug("%s", str(exc))
            return ExecTxDoneCode.NonceTooHigh

    async def complete_stuck_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxDoneCode:
        if not await ctx.holder_validator.is_active():
            return ExecTxDoneCode.Failed

        # get solana address of the sender and receiver
        await self._init_base_sol_tx(ctx)

        await self._emulate_neon_tx(ctx, re_emulate=True)

        acct_list = await self._sol_client.get_account_list(ctx.stuck_alt_address_list)
        for acct in acct_list:
            if (alt_acct := SolAltAccountInfo.from_bytes(acct.address, acct.data)).is_exist:
                ctx.add_alt_id(alt_acct.ident)

        return await self._select_strategy(ctx, self._stuck_tx_strategy_list)

    async def _select_strategy(self, ctx: NeonExecTxCtx, tx_strategy_list: _BaseTxStrategyList) -> ExecTxDoneCode:
        for _Strategy in tx_strategy_list:
            if ctx.skip_simple_strategy and _Strategy.is_simple:
                # _LOG.debug("skip simple strategy %s", _Strategy.name)
                continue

            strategy = _Strategy(self._server, ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.name, strategy.validation_error_msg)
                continue

            _LOG.debug("use strategy %s", strategy.name)
            if (exit_code := await self._exec_neon_tx(ctx, strategy)) is not None:
                await self._done_exec_neon_tx(strategy)
                # _LOG.debug("done strategy %s with result %s", strategy.name, exit_code.name)
                return exit_code

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxDoneCode.Failed

    async def _exec_neon_tx(self, ctx: NeonExecTxCtx, strategy: BaseTxStrategy) -> ExecTxDoneCode | None:
        for _retry in itertools.count():
            # if retry > 0:
            #     _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                if await self._is_completed(ctx):
                    return ExecTxDoneCode.Done

                if not await strategy.prep_before_emulation():
                    continue
                if ctx.has_holder_block and (not ctx.holder.block.is_empty):
                    await self._emulate_neon_tx(ctx, re_emulate=True)
                if not await strategy.update_after_emulation():
                    continue

                # NeonTx is prepared for the execution
                ctx.holder_validator.mark_complete_prepare()
                return await strategy.execute()

            except (EthNonceTooLowError, EthNonceTooHighError):
                raise

            except SkdTxError:
                raise

            except StuckTxError as exc:
                _LOG.warning("stuck NeonTx error: %s", str(exc))
                raise

            except (
                WrongStrategyError,
                SolCbExceededError,
                SolNeonRequireResizeIterError,
                SolTxSizeError,
            ) as _exc:
                ctx.mark_skip_simple_strategy()
                # _LOG.debug("wrong strategy error: %s", str(exc))
                return None

            except (
                EthError,
                SolCbExceededCriticalError,
                SolOutOfMemoryError,
                SolUnknownReceiptError,
                SolNoMoreRetriesError,
            ) as exc:
                ctx.mark_skip_simple_strategy()
                _LOG.debug("execution error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(strategy)

            except SolError as exc:
                # _LOG.debug("simple retry error: %s", str(exc), extra=self._msg_filter)
                await asyncio.sleep(self._wait_sec)

            except BaseException as exc:
                ctx.mark_skip_simple_strategy()
                _LOG.debug("unexpected error: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(strategy)

    async def _cancel_neon_tx(self, strategy: BaseTxStrategy) -> ExecTxDoneCode | None:
        for _retry in range(self._cfg.retry_on_fail):
            # if retry > 0:
            #     _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel()

            except (SolNoMoreRetriesError, SolBlockhashNotFound):
                await asyncio.sleep(self._wait_sec)

            except (BaseException,) as _exc:
                # _LOG.error(
                #     "unexpected error on cancel NeonTx",
                #     exc_info=exc,
                #     extra=self._msg_filter,
                # )
                return None

    @staticmethod
    async def _done_exec_neon_tx(strategy: BaseTxStrategy) -> None:
        try:
            await strategy.done_execution()
        except (BaseException,) as _exc:
            # _LOG.error(
            #     "unexpected error on done exec NeonTx",
            #     exc_info=exc,
            #     extra=self._msg_filter,
            # )
            pass

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx, *, re_emulate: bool = False) -> None:
        # update evm config
        evm_cfg = await self._server.get_evm_cfg()

        if re_emulate:
            sender_balance = (await self._core_api_client.get_neon_account(ctx.sender, None)).balance
        else:
            sender_balance = None

        emul_resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            ctx.holder_tx,
            preload_sol_address_list=ctx.account_key_list,
            check_result=False,
            sender_balance=sender_balance,
            emulator_block=ctx.holder.block,
        )

        ctx.set_emulator_result(emul_resp)

        # # get executable accounts
        # acct_list = await self._sol_client.get_account_list(ctx.account_key_list, 1)
        # ro_addr_list = [acct.address for acct in acct_list if acct.executable]
        # ctx.set_ro_address_list(ro_addr_list)

    @staticmethod
    async def _is_completed(ctx: NeonExecTxCtx) -> bool:
        if not ctx.is_scheduled_tx:
            return False

        status = await ctx.skd_tree_parser.get_neon_skd_status(ctx.holder_tx.index)
        return status not in (status.NotStarted, status.ToStart, status.ToSkip, status.InProgress)

    async def _init_base_sol_tx(self, ctx: NeonExecTxCtx) -> None:
        addr_list = [ctx.payer, ctx.sender, ctx.receiver]
        acct_list = await self._core_api_client.get_neon_account_list(addr_list, None)

        if not ctx.is_stuck_tx:
            state_tx_cnt = acct_list[0].state_tx_cnt
            EthNonceTooHighError.raise_if_error(ctx.holder_tx.nonce, state_tx_cnt, sender=ctx.sender.eth_address)

        base_tx_acct_set = NeonBaseTxAccountSet(
            payer=acct_list[0].sol_address,
            sender=acct_list[1].sol_address,
            receiver=acct_list[2].sol_address,
            receiver_contract=acct_list[2].contract_sol_address,
            payer_balance=acct_list[0].balance,
        )
        ctx.set_tx_sol_address(base_tx_acct_set)

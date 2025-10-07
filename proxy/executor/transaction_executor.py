from __future__ import annotations

import asyncio
import logging
from typing import Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.cancel_error import CancelErrorData
from common.neon.neon_program import NeonBaseTxAccountSet
from common.neon_rpc.api import CoreApiBlockModel
from common.neon_rpc.errors import (
    SolNeonSkdTxError,
    SolNeonRequireResizeIterError,
    SolNeonMissingAccountError,
)
from common.solana.alt_program import SolAltAccountInfo
from common.solana.cb_program import SolCbCfg
from common.solana.errors import SolTxSizeError, SolError
from common.solana_rpc.errors import (
    SolNoMoreRetriesError,
    SolBlockhashNotFound,
    SolWritableError,
    SolTxExecError,
    SolUnsupportedProgError,
)
from .errors import StuckTxError, WrongStrategyError
from .server_abc import ExecutorComponent
from .strategy_base import BaseTxStrategy
from .strategy_iterative import IterativeTxStrategy, AltIterativeTxStrategy
from .strategy_iterative_holder import HolderTxStrategy, AltHolderTxStrategy
from .strategy_iterative_no_chain_id import NoChainIdTxStrategy, AltNoChainIdTxStrategy
from .strategy_iterative_scheduled import ScheduledTxStrategy, AltScheduledTxStrategy
from .strategy_iterative_scheduled_holder import ScheduledHolderTxStrategy, AltScheduledHolderTxStrategy
from .strategy_simple import SimpleTxStrategy, AltSimpleTxStrategy
from .strategy_simple_holder import SimpleHolderTxStrategy, AltSimpleHolderTxStrategy
from .strategy_simple_solana_call import SimpleTxSolanaCallStrategy, AltSimpleTxSolanaCallStrategy
from .strategy_simple_solana_call_holder import SimpleHolderTxSolanaCallStrategy, AltSimpleHolderTxSolanaCallStrategy
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)
_BaseTxStrategyList = list[type[BaseTxStrategy]]


class NeonTxExecutor(ExecutorComponent):
    _wait_sec: Final[float] = max(ONE_BLOCK_SEC / 2, 0.05)

    _TxStrategyList: Final[_BaseTxStrategyList] = [
        # single iteration
        SimpleTxStrategy,
        #     + holder
        SimpleHolderTxStrategy,
        # single iteration with Solana Call
        SimpleTxSolanaCallStrategy,
        #     + holder
        SimpleHolderTxSolanaCallStrategy,
        # multi-iteration
        IterativeTxStrategy,
        #     + holder
        HolderTxStrategy,
        # wo-chain-id
        #     + multi-iteration
        #     + holder
        NoChainIdTxStrategy,
        # scheduled
        ScheduledTxStrategy,
        #     + holder
        ScheduledHolderTxStrategy,
        # ALT strategies:
        #     simple + solana + alt
        SimpleHolderTxSolanaCallStrategy,
        #     simple + solana + alt + holder
        AltSimpleHolderTxSolanaCallStrategy,
        #     simple + alt
        AltSimpleTxStrategy,
        #     simple + alt + holder
        AltSimpleHolderTxStrategy,
        #     simple + solana + alt
        AltSimpleTxSolanaCallStrategy,
        #     simple + solana + alt + holder
        AltSimpleHolderTxSolanaCallStrategy,
        #     multi-iterative + alt
        AltIterativeTxStrategy,
        #     multi-iterative + alt + holder
        AltHolderTxStrategy,
        #     multi-iterative + wo-chain-id + alt + holder
        AltNoChainIdTxStrategy,
        #     multi-iterative + scheduled + alt
        AltScheduledTxStrategy,
        #     multi-iterative + scheduled + alt + holder
        AltScheduledHolderTxStrategy,
    ]

    _StuckTxStrategyList: Final[_BaseTxStrategyList] = [
        # multi-iteration
        #     + holder
        HolderTxStrategy,
        #     + alt + holder
        AltHolderTxStrategy,
        # scheduled
        #     + holder
        ScheduledHolderTxStrategy,
        #     + alt + holder
        AltScheduledHolderTxStrategy,
    ]

    async def exec_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxDoneCode:
        await ctx.holder_validator.validate_no_stuck_tx()

        try:
            await self._init_base_sol_tx(ctx)
            await self._emulate_neon_tx(ctx)

            if not self._is_valid_tx(ctx):
                return ExecTxDoneCode.Failed

            return await self._select_strategy(ctx, self._TxStrategyList)

        except EthNonceTooLowError as _exc:
            # _LOG.debug("%s", str(exc))
            return ExecTxDoneCode.NonceTooLow

        except EthNonceTooHighError as _exc:
            # _LOG.debug("%s", str(exc))
            return ExecTxDoneCode.NonceTooHigh

    async def complete_stuck_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxDoneCode:
        if not await ctx.holder_validator.has_active_stuck_tx():
            return ExecTxDoneCode.Failed

        # refresh the ALT list, some of them can be destroyed
        acct_list = await self._sol_client.get_account_list(ctx.stuck_alt_address_list)
        for acct in acct_list:
            if (alt_acct := SolAltAccountInfo.from_account_nothrow(acct)).is_exist:
                ctx.add_alt_id(alt_acct.ident)

        # get solana address of the sender and receiver
        await self._init_base_sol_tx(ctx)

        if not await ctx.holder_validator.has_active_stuck_tx():
            return ExecTxDoneCode.Failed
        await self._emulate_neon_tx(ctx)

        if self._is_valid_tx(ctx):
            return ExecTxDoneCode.Failed

        return await self._select_strategy(ctx, self._StuckTxStrategyList)

    async def destroy_tree_account(self, ctx: NeonExecTxCtx) -> None:
        await self._init_base_sol_tx(ctx)
        try:
            await self._destroy_tree_account_retry_loop(ctx)
            await asyncio.sleep(self._wait_sec)

        except (SolTxExecError, SolNeonSkdTxError):
            pass

        except BaseException as exc:
            _LOG.error("error on destroy tree account: %s", str(exc))

        finally:
            await self._delete_tree_account_from_db(ctx)

    async def _select_strategy(self, ctx: NeonExecTxCtx, tx_strategy_list: _BaseTxStrategyList) -> ExecTxDoneCode:
        for _Strategy in tx_strategy_list:
            if ctx.skip_simple_strategy and _Strategy.IsSimple:
                # _LOG.debug("skip simple strategy %s", _Strategy.name)
                continue

            strategy = _Strategy(self._server, ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.Name, strategy.validation_error_msg)
                continue

            _LOG.debug("use strategy %s", strategy.Name)
            if (exit_code := await self._exec_neon_tx(ctx, strategy)) is not None:
                await self._done_exec_neon_tx(strategy)
                # _LOG.debug("done strategy %s with result %s", strategy.name, exit_code.name)
                return exit_code

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxDoneCode.Failed

    async def _exec_neon_tx(self, ctx: NeonExecTxCtx, strategy: BaseTxStrategy) -> ExecTxDoneCode | None:
        re_emulate = False

        ctx.reset_tx_exec_state()
        while True:
            # if retry > 0:
            #     _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                if await ctx.is_finalized_tx():
                    return ExecTxDoneCode.Done

                if re_emulate:
                    re_emulate = False
                    await asyncio.sleep(self._wait_sec)
                    await ctx.holder_validator.refresh()

                    await self._emulate_neon_tx(ctx)

                if not await strategy.prep_execution():
                    continue
                elif await ctx.is_finalized_tx():
                    return ExecTxDoneCode.Done

                await ctx.mark_complete_prepare()
                return await strategy.execute()

            except SolNeonSkdTxError:
                return ExecTxDoneCode.Failed

            except (EthError, StuckTxError):
                raise

            except (WrongStrategyError, SolTxSizeError, SolNeonRequireResizeIterError) as exc:
                if not strategy.IsSimple:
                    _LOG.error("unexpected fail: %s", exc_info=exc, extra=self._msg_filter)
                return None

            except (SolNeonMissingAccountError, SolWritableError, SolUnsupportedProgError):
                ctx.mark_skip_simple_strategy()
                if strategy.IsSimple:
                    return None

                re_emulate = True

            except SolTxExecError as exc:
                _LOG.debug("execution fail: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(ctx, strategy, exc.data)

            except SolError:
                # ALT errors and other staff
                # _LOG.debug("simple retry fail: %s", str(exc), extra=self._msg_filter)
                re_emulate = True

            except BaseException as exc:
                _LOG.error(
                    "unexpected fail on transaction execution: %s",
                    str(exc),
                    extra=self._msg_filter,
                    exc_info=exc,
                )
                return await self._cancel_neon_tx(ctx, strategy, CancelErrorData.default())

    async def _cancel_neon_tx(
        self,
        ctx: NeonExecTxCtx,
        strategy: BaseTxStrategy,
        data: CancelErrorData,
    ) -> ExecTxDoneCode | None:
        ctx.mark_skip_simple_strategy()
        if strategy.IsSimple:
            return None

        while True:
            # if retry > 0:
            #     _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel(data)

            except SolNeonSkdTxError:
                return ExecTxDoneCode.Failed

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

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx) -> None:
        # update evm config
        if ctx.is_started_tx:
            emul_resp = await self._core_api_client.emulate_from_holder(ctx.holder_address)
        else:
            emul_resp = await self._core_api_client.emulate_neon_call(ctx.holder_tx, check_result=False)

        await ctx.set_emulator_result(emul_resp)

    @staticmethod
    def _is_valid_tx(ctx: NeonExecTxCtx) -> bool:
        if ctx.has_sol_call and ctx.holder_tx.is_fee_less:
            _LOG.debug("fail to execute fee-less transaction with the Solana call")
            return False
        return True

    async def _init_base_sol_tx(self, ctx: NeonExecTxCtx) -> None:
        addr_list: Final = [ctx.payer, ctx.sender, ctx.receiver]
        acct_list: Final = await self._core_api_client.get_neon_account_list(addr_list, None)

        payer, sender, receiver = acct_list

        if ctx.is_root_tx and (not ctx.is_started_tx):
            state_tx_cnt: Final = payer.state_tx_cnt
            EthNonceTooHighError.raise_if_error(ctx.holder_tx.nonce, state_tx_cnt, sender=ctx.sender.eth_address)

        base_tx_acct_set = NeonBaseTxAccountSet(
            raw_payer=payer.sol_address,
            raw_payer_container=payer.container_sol_address,
            raw_sender=sender.sol_address,
            raw_sender_container=sender.container_sol_address,
            raw_receiver=receiver.sol_address,
            raw_receiver_container=receiver.container_sol_address,
            receiver_contract=receiver.contract_sol_address,
            payer_balance=payer.balance,
        )
        ctx.set_tx_sol_address(base_tx_acct_set)

    @staticmethod
    async def _destroy_tree_account_retry_loop(ctx: NeonExecTxCtx) -> None:
        skd_tree: Final = ctx.skd_tree_parser
        destroy_ix: Final = ctx.neon_prog.make_destroy_skd_tree_ix()
        destroy_cfg: Final = SolCbCfg(max_priority_fee=ctx.max_sol_priority_fee)

        while True:
            if not (await skd_tree.is_exist()):
                break
            elif not (await skd_tree.can_be_destroyed()):
                break

            if not await ctx.recheck_sol_tx_list(destroy_ix.name):
                await ctx.send_sol_tx_list(destroy_ix, destroy_cfg)

    async def _delete_tree_account_from_db(self, ctx: NeonExecTxCtx) -> None:
        skd_tree: Final = ctx.skd_tree_parser
        for retry in range(self._cfg.retry_on_fail):
            try:
                if not await skd_tree.is_exist():
                    await self._db.destroy_tree_account(skd_tree.address, skd_tree.root_neon_tx_hash)
                    return

                await asyncio.sleep(self._wait_sec)
            except BaseException as exc:
                _LOG.error("error on delete tree row from db", exc_info=exc, extra=self._msg_filter)

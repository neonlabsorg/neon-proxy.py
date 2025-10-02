from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar, Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.cancel_error import CancelErrorData
from common.neon.neon_program import NeonBaseTxAccountSet, NeonEvmIxCode
from common.neon_rpc.errors import SolNeonSkdTxError, SolNeonRequireResizeIterError, SolNeonMissingAccountError
from common.solana.alt_program import SolAltAccountInfo
from common.solana.cb_program import SolCbCfg, SolCbProg
from common.solana.errors import SolTxSizeError, SolError
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import (
    SolCbExceededError,
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

        except SolNeonSkdTxError as _exc:
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
            if (alt_acct := SolAltAccountInfo.from_account_nothrow(acct)).is_exist:
                ctx.add_alt_id(alt_acct.ident)

        try:
            return await self._select_strategy(ctx, self._stuck_tx_strategy_list)

        except SolNeonSkdTxError:
            return ExecTxDoneCode.Failed

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
        re_emulate = False

        ctx.reset_tx_exec_state()
        for _retry in itertools.count():
            # if retry > 0:
            #     _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                if await self._is_completed(ctx):
                    return ExecTxDoneCode.Done

                if re_emulate:
                    await self._emulate_neon_tx(ctx, re_emulate)
                    re_emulate = False

                if not await strategy.prep_before_exec():
                    continue

                # NeonTx is prepared for the execution
                ctx.holder_validator.mark_complete_prepare()
                return await strategy.execute()

            except (EthError, SolNeonSkdTxError):
                raise

            except StuckTxError as exc:
                _LOG.warning("stuck NeonTx fail: %s", str(exc))
                raise

            except (SolCbExceededError, SolNeonRequireResizeIterError):
                ctx.mark_skip_simple_strategy()
                return None

            except (WrongStrategyError, SolTxSizeError):
                return None

            except (SolNeonMissingAccountError, SolWritableError, SolUnsupportedProgError):
                ctx.mark_skip_simple_strategy()
                if strategy.is_simple:
                    return None

                re_emulate = True
                await asyncio.sleep(self._wait_sec)
                await ctx.holder_validator.refresh()

            except SolTxExecError as exc:
                # _LOG.debug("execution fail: %s", str(exc), extra=self._msg_filter)
                return await self._cancel_neon_tx(ctx, strategy, exc.data)

            except SolError:
                # _LOG.debug("simple retry fail: %s", str(exc), extra=self._msg_filter)
                re_emulate = True
                await asyncio.sleep(self._wait_sec)

            except BaseException as exc:
                _LOG.debug("unexpected fail on transaction execution: %s", str(exc), extra=self._msg_filter, exc_info=exc)
                return await self._cancel_neon_tx(ctx, strategy, CancelErrorData.default())
        assert False, "unreached code"

    async def _cancel_neon_tx(
        self,
        ctx: NeonExecTxCtx,
        strategy: BaseTxStrategy,
        data: CancelErrorData,
    ) -> ExecTxDoneCode | None:
        ctx.mark_skip_simple_strategy()
        if strategy.is_simple:
            return None

        for _retry in range(self._cfg.retry_on_fail):
            # if retry > 0:
            #     _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel(data)

            except (SolNoMoreRetriesError, SolBlockhashNotFound):
                await asyncio.sleep(self._wait_sec)

            except (BaseException,) as _exc:
                # _LOG.error(
                #     "unexpected error on cancel NeonTx",
                #     exc_info=exc,
                #     extra=self._msg_filter,
                # )
                return None
        assert False, "unreached code"

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

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx, re_emulate: bool = False) -> None:
        # update evm config
        if re_emulate:
            sender_balance = (await self._core_api_client.get_neon_account(ctx.sender, None)).balance
        else:
            sender_balance = None

        emul_resp = await self._core_api_client.emulate_neon_call(
            ctx.holder_tx,
            preload_sol_address_list=ctx.account_key_list,
            check_result=False,
            sender_balance=sender_balance,
            emulator_block=ctx.holder_block,
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

        payer, sender, receiver = acct_list

        if not ctx.is_stuck_tx:
            state_tx_cnt = payer.state_tx_cnt
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

    async def _destroy_tree_account_retry_loop(self, ctx: NeonExecTxCtx) -> None:
        skd_tree: Final = ctx.skd_tree_parser
        tx_list_sender: Final = ctx.sol_tx_list_sender

        destroy_ix: Final = ctx.neon_prog.make_destroy_skd_tree_ix()
        destroy_cfg: Final = SolCbCfg(
            NeonEvmIxCode.SkdTreeDestroy.name,
            cu_price=self._cfg.def_simple_cu_price,
            cu_limit=ctx.neon_prog.CuLimitSkdTreeAccountDestroy,
        )
        tx: SolLegacyTx | None = None

        while True:
            if not (await skd_tree.is_exist()):
                break
            elif not (await skd_tree.can_be_destroyed()):
                break

            if not tx:
                tx = SolCbProg.make_legacy_tx(destroy_cfg, destroy_ix)

            if (not tx.is_signed) or (not tx_list_sender.recheck(tx)):
                await tx_list_sender.send(tx)

            tx_state_list = tx_list_sender.success_tx_state_list
            tx = tx_state_list[0] if tx_state_list else None

    async def _delete_tree_account_from_db(self, ctx: NeonExecTxCtx) -> None:
        skd_tree: Final = ctx.skd_tree_parser
        try:
            if await skd_tree.is_exist():
                raise SolError("tree account is not deleted yet")

            await self._db.destroy_tree_account(skd_tree.address, skd_tree.neon_tx_hash)
        except BaseException as exc:
            _LOG.error("error on delete tree row from db", exc_info=exc, extra=self._msg_filter)

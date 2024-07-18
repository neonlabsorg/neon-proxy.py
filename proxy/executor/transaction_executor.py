from __future__ import annotations

import asyncio
import itertools
import logging
from typing import ClassVar

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.errors import EthError, EthNonceTooHighError, EthNonceTooLowError
from common.neon.account import NeonAccount
from common.neon_rpc.api import CoreApiTxModel
from common.solana.alt_program import SolAltAccountInfo
from common.solana.commit_level import SolCommit
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
from .errors import BadResourceError, StuckTxError, WrongStrategyError
from .holder_validator import HolderAccountValidator
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
from ..base.ex_api import ExecTxResp, ExecTxRespCode

_LOG = logging.getLogger(__name__)
_BaseTxStrategyList = list[type[BaseTxStrategy]]


class NeonTxExecutor(ExecutorComponent):
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

    async def exec_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxResp:
        holder_validator = HolderAccountValidator(self._core_api_client, ctx.holder_address, ctx.neon_tx_hash)
        if (holder := await holder_validator.refresh()).is_active:
            _LOG.debug(
                "holder %s contains stuck NeonTx %s",
                ctx.holder_address,
                holder_validator.holder_account.neon_tx_hash,
            )
            raise StuckTxError(holder)

        try:
            await self._init_sender_sol_address(ctx, ctx.sender)
            # the earlier check of the nonce
            await self._validate_nonce(ctx)
            # get the list of accounts for validation
            await self._emulate_neon_tx(ctx)

            exit_code = await self._select_strategy(ctx, self._tx_strategy_list)
            state_tx_cnt = await self._get_state_tx_cnt(ctx)

        except EthNonceTooLowError as exc:
            _LOG.debug("%s", str(exc))
            exit_code = ExecTxRespCode.NonceTooLow
            state_tx_cnt = exc.state_tx_cnt

        except EthNonceTooHighError as exc:
            _LOG.debug("%s", str(exc))
            exit_code = ExecTxRespCode.NonceTooHigh
            state_tx_cnt = exc.state_tx_cnt

        return ExecTxResp(code=exit_code, state_tx_cnt=state_tx_cnt)

    async def complete_stuck_neon_tx(self, ctx: NeonExecTxCtx) -> ExecTxResp:
        holder_validator = HolderAccountValidator(self._core_api_client, ctx.holder_address, ctx.neon_tx_hash)
        if not (holder := await holder_validator.refresh()).is_active:
            return ExecTxResp(code=ExecTxRespCode.Failed)

        # update NeonProg settings from EVM config
        evm_cfg = await self._server.get_evm_cfg()
        ctx.init_neon_prog(evm_cfg)

        # request the token address (based on chain-id) for receiving payments from user
        token_sol_addr = await self._op_client.get_token_sol_address(ctx.req_id, ctx.payer, holder.chain_id)
        ctx.set_token_sol_address(token_sol_addr)

        # get solana address of the user
        await self._init_sender_sol_address(ctx, holder.sender)

        ctx.set_holder_account(holder)
        await self._emulate_neon_tx(ctx)

        acct_list = await self._sol_client.get_account_list(ctx.stuck_alt_address_list)
        for acct in acct_list:
            alt_acct = SolAltAccountInfo.from_bytes(acct.address, acct.data)
            if not alt_acct.is_empty:
                ctx.add_alt_id(alt_acct.ident)

        exit_code = await self._select_strategy(ctx, self._stuck_tx_strategy_list)
        return ExecTxResp(code=exit_code, chain_id=holder.chain_id)

    async def _select_strategy(self, ctx: NeonExecTxCtx, tx_strategy_list: _BaseTxStrategyList) -> ExecTxRespCode:
        for _Strategy in tx_strategy_list:
            if ctx.skip_simple_strategy and _Strategy.is_simple:
                _LOG.debug("skip simple strategy %s", _Strategy.name)
                continue

            strategy = _Strategy(ctx)
            if not await strategy.validate():
                _LOG.debug("skip strategy %s: %s", strategy.name, strategy.validation_error_msg)
                continue

            _LOG.debug("use strategy %s", strategy.name)
            if (exit_code := await self._exec_neon_tx(ctx, strategy)) is not None:
                _LOG.debug("done strategy %s with result %s", strategy.name, exit_code.name)
                return exit_code

        _LOG.warning("didn't find a strategy for execution, NeonTx is too big for execution?")
        return ExecTxRespCode.Failed

    async def _exec_neon_tx(self, ctx: NeonExecTxCtx, strategy: BaseTxStrategy) -> ExecTxRespCode | None:
        for retry in itertools.count():
            if retry > 0:
                _LOG.debug("attempt %s to execute %s, ...", retry + 1, strategy.name)

            try:
                has_changes = await strategy.prep_before_emulate()
                if not ctx.is_stuck_tx:
                    await self._validate_nonce(ctx)
                    await self._emulate_neon_tx(ctx)

                if has_changes:
                    await strategy.update_after_emulate()
                    # Preparations made changes in the Solana state -> repeat the preparation and emulation
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

            except (
                WrongStrategyError,
                SolCbExceededError,
                SolNeonRequireResizeIterError,
                SolTxSizeError,
            ) as exc:
                ctx.mark_skip_simple_strategy()
                _LOG.debug("wrong strategy error: %s", str(exc))
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
                _LOG.debug("simple error: %s", str(exc), extra=self._msg_filter)
                await asyncio.sleep(ONE_BLOCK_SEC / 2)

            except BaseException as exc:
                ctx.mark_skip_simple_strategy()
                _LOG.debug("unexpected error", extra=self._msg_filter, exc_info=exc)
                return await self._cancel_neon_tx(strategy)

    async def _cancel_neon_tx(self, strategy: BaseTxStrategy) -> ExecTxRespCode | None:
        for retry in range(self._cfg.retry_on_fail):
            if retry > 0:
                _LOG.debug("cancel NeonTx, attempt %s...", retry + 1)

            try:
                return await strategy.cancel()

            except (SolNoMoreRetriesError, SolBlockhashNotFound):
                await asyncio.sleep(ONE_BLOCK_SEC)

            except BaseException as exc:
                _LOG.error(
                    "unexpected error on cancel NeonTx",
                    exc_info=exc,
                    extra=self._msg_filter,
                )
                return None

    async def _emulate_neon_tx(self, ctx: NeonExecTxCtx) -> None:
        # don't emulate if the slot is the same
        slot = await self._sol_client.get_slot(SolCommit.Confirmed)
        if slot == ctx.emulator_slot:
            return

        # update evm config
        evm_cfg = await self._server.get_evm_cfg()
        ctx.init_neon_prog(evm_cfg)

        if ctx.is_stuck_tx:
            core_tx = ctx.holder_tx
        else:
            core_tx = CoreApiTxModel.from_neon_tx(ctx.neon_tx, ctx.chain_id)

        emul_resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            core_tx,
            preload_sol_address_list=ctx.account_key_list,
            check_result=False,
        )

        slot = await self._sol_client.get_slot(SolCommit.Confirmed)
        ctx.set_emulator_result(slot, emul_resp)

        # get executable accounts
        acct_list = await self._sol_client.get_account_list(ctx.account_key_list, 1)
        ro_addr_list = [acct.address for acct in acct_list if acct.executable]
        ctx.set_ro_address_list(ro_addr_list)

    async def _validate_nonce(self, ctx: NeonExecTxCtx) -> None:
        if ctx.has_good_sol_tx_receipt:
            return

        state_tx_cnt = await self._get_state_tx_cnt(ctx)
        EthNonceTooHighError.raise_if_error(ctx.neon_tx.nonce, state_tx_cnt)
        EthNonceTooLowError.raise_if_error(ctx.neon_tx.nonce, state_tx_cnt)

    async def _get_state_tx_cnt(self, ctx: NeonExecTxCtx) -> int:
        acct = await self._core_api_client.get_neon_account(ctx.sender, None)
        return acct.state_tx_cnt

    async def _init_sender_sol_address(self, ctx: NeonExecTxCtx, sender: NeonAccount) -> None:
        acct = await self._core_api_client.get_neon_account(sender, None)
        ctx.set_sender_sol_address(acct.sol_address)

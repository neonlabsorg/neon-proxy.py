from __future__ import annotations

import logging

from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import HolderAccountModel, HolderAccountStatus
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import SolNoMoreRetriesError
from common.solana_rpc.transaction_list_sender import SolTxSendState
from .errors import StuckTxError
from .strategy_base import BaseTxStrategy
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from ..base.ex_api import ExecTxRespCode

_LOG = logging.getLogger(__name__)


class IterativeTxStrategy(BaseTxStrategy):
    name = NeonEvmIxCode.TxStepFromData.name
    _cancel_name = NeonEvmIxCode.CancelWithHash.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._completed_evm_step_cnt = 0

    @property
    def _cu_price(self) -> int:
        # Apply priority fee only in iterative transactions
        return self._ctx.cfg.cu_price

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if not await self._recheck_tx_list(self.name):
            if not self._ctx.is_stuck_tx:
                await self._send_tx_list(self._build_execute_tx_list())

        # Not enough iterations, try `retry_on_fail` times to complete the Neon Tx
        retry_on_fail = self._ctx.cfg.retry_on_fail
        for retry in range(retry_on_fail):
            if (exit_code := await self._decode_neon_tx_return()) is not None:
                return exit_code

            _LOG.debug("no receipt -> execute additional iterations...")
            await self._send_tx_list(self._build_execute_tx_list())

        raise SolNoMoreRetriesError()

    async def cancel(self) -> ExecTxRespCode | None:
        if (await self._recheck_tx_list(self._cancel_name)) or (await self._send_tx_list(self._build_cancel_tx_list())):
            return ExecTxRespCode.Failed

        _LOG.error("no!? cancel tx")
        return None

    def _build_execute_tx_list(self) -> list[SolTx]:
        if self._completed_evm_step_cnt:
            evm_step_cnt = self._ctx.total_evm_step_cnt - self._completed_evm_step_cnt
            iter_cnt = max(evm_step_cnt // self._ctx.evm_step_cnt_per_iter, 1)
        else:
            iter_cnt = self._ctx.iter_cnt

        tx_list: list[SolTx] = [self._build_tx() for _ in range(iter_cnt)]

        _LOG.debug(
            "%s iterations: %s total EVM steps, %s completed EVM steps, %s EVM steps per iteration",
            len(tx_list),
            self._ctx.total_evm_step_cnt,
            self._completed_evm_step_cnt,
            self._ctx.evm_step_cnt_per_iter,
        )

        return tx_list

    async def _validate(self) -> bool:
        return self._validate_not_stuck_tx() and self._validate_no_sol_call() and self._validate_has_chain_id()

    def _build_tx(self) -> SolLegacyTx:
        evm_step_cnt = self._ctx.evm_step_cnt_per_iter
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_data_ix(evm_step_cnt, uniq_idx))

    def _build_cancel_tx(self) -> SolLegacyTx:
        prog = self._ctx.neon_prog
        return self._build_cu_tx(name="CancelWithHash", ix=prog.make_cancel_ix())

    async def _decode_neon_tx_return(self) -> ExecTxRespCode | None:
        tx_state_list = self._ctx.sol_tx_list_sender.tx_state_list
        total_gas_used = 0
        has_already_finalized = False
        status = SolTxSendState.Status

        for tx_state in tx_state_list:
            if tx_state.status == status.AlreadyFinalizedError:
                has_already_finalized = True
                _LOG.debug("found AlreadyFinalizedError in %s", tx_state.tx)
                continue
            elif tx_state.status != status.GoodReceipt:
                continue
            elif not (sol_neon_ix := self._find_sol_neon_ix(tx_state)):
                _LOG.warning("no? NeonTx instruction in %s", tx_state.tx)
                continue
            elif not sol_neon_ix.neon_tx_return.is_empty:
                _LOG.debug("found NeonTx-Return in %s", sol_neon_ix)
                return ExecTxRespCode.Done

            total_gas_used = max(total_gas_used, sol_neon_ix.neon_total_gas_used)

        if has_already_finalized:
            return ExecTxRespCode.Failed

        if await self._is_finalized_holder():
            return ExecTxRespCode.Failed

        return None

    def _build_cancel_tx_list(self) -> list[SolTx]:
        return [self._build_cancel_tx()]

    async def _is_finalized_holder(self) -> bool:
        holder = await self._get_holder_acct()
        _LOG.debug("holder %s", holder)
        if holder.status == HolderAccountStatus.Finalized:
            if holder.neon_tx_hash == self._ctx.neon_tx_hash:
                _LOG.warning("holder %s has finalized tag", holder.address)
                return True
        elif holder.status == HolderAccountStatus.Active:
            if holder.neon_tx_hash != self._ctx.neon_tx_hash:
                raise StuckTxError(holder.neon_tx_hash, holder.chain_id, holder.address)
            _LOG.debug("holder %s has %s completed EVM steps", holder.address, holder.evm_step_cnt)
            self._completed_evm_step_cnt = holder.evm_step_cnt
        else:
            self._completed_evm_step_cnt = 0
        return False

    async def _get_holder_acct(self) -> HolderAccountModel:
        return await self._ctx.core_api_client.get_holder_account(self._ctx.holder_address)


@alt_strategy
class AltIterativeTxStrategy(IterativeTxStrategy):
    pass

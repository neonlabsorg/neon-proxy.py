from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final, ClassVar

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
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromData.name
    _cancel_name: ClassVar[str] = NeonEvmIxCode.CancelWithHash.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._completed_evm_step_cnt = 0

    @property
    def _cu_price(self) -> int:
        # Apply priority fee only in iterative transactions
        return self._ctx.cfg.cu_price

    @property
    def _def_evm_step_cnt(self) -> int:
        return self._ctx.evm_step_cnt_per_iter

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if not await self._recheck_tx_list(self.name):
            if not self._ctx.is_stuck_tx:
                await self._emulate_and_send_tx_list()

        # Not enough iterations, try `retry_on_fail` times to complete the Neon Tx
        retry_on_fail = self._ctx.cfg.retry_on_fail
        for retry in range(retry_on_fail):
            if (exit_code := await self._decode_neon_tx_return()) is not None:
                return exit_code

            _LOG.debug("no receipt -> execute additional iterations...")
            await self._emulate_and_send_tx_list()

        raise SolNoMoreRetriesError()

    async def cancel(self) -> ExecTxRespCode | None:
        if await self._recheck_tx_list(self._cancel_name):
            # cancel is completed
            return ExecTxRespCode.Failed

        holder = await self._get_holder_acct()
        if (holder.status != HolderAccountStatus.Active) or (holder.neon_tx_hash != self._ctx.neon_tx_hash):
            _LOG.debug("holder %s doesn't contain %s NeonTx", holder.address, self._ctx.neon_tx_hash)
            return ExecTxRespCode.Failed

        if await self._send_tx_list([self._build_cancel_tx()]):
            return ExecTxRespCode.Failed

        _LOG.error("no!? cancel tx")
        return None

    async def _emulate_and_send_tx_list(self) -> bool:
        if self._ctx.is_stuck_tx:
            iter_info = self._get_stuck_evm_step_cnt()
        elif self._ctx.cfg.calc_cu_limit_usage:
            iter_info = await self._calc_evm_step_cnt()
        else:
            iter_info = self._get_def_evm_step_cnt()

        tx_list: list[SolTx] = [
            self._build_tx(is_finalized=iter_info.is_finalized, step_cnt=iter_info.step_cnt)
            for _ in range(iter_info.iter_cnt)
        ]
        return await self._send_tx_list(tx_list)

    async def _calc_evm_step_cnt(self) -> _IterInfo:
        step_cnt_iter = self._ctx.evm_step_cnt_per_iter
        total_step_cnt = self._ctx.total_evm_step_cnt - self._completed_evm_step_cnt + 1

        _LOG.debug(
            "%s total EVM steps, %s completed EVM steps, %s EVM steps per iteration",
            self._ctx.total_evm_step_cnt,
            self._completed_evm_step_cnt,
            step_cnt_iter,
        )

        if not total_step_cnt:
            _LOG.debug("just 1 finalization iteration")
            return self._IterInfo(True, step_cnt_iter, 1)

        max_used_cu_limit: Final[int] = int(self._cu_limit * 0.85)  # 85% of the maximum
        max_iter_cnt: Final[int] = max((total_step_cnt + step_cnt_iter - 1) // step_cnt_iter, 1)
        mult_factor: Final[int] = max_iter_cnt * 2
        step_cnt = total_step_cnt

        # 5? attempts looks enough for evm steps calculations:
        #   1 attempt:
        #      - emulate the whole NeonTx in 1 iteration with the huge CU-limit
        #      - get the total-CU-usage for the whole NeonTx
        #      - divide the total-CU-usage on 85% of CU-limit of SolTx
        #      - get the number of iterations
        #      - divide the total-EVM-steps on the number of iterations
        #
        #   2 attempt:
        #      - emulate the divided iterations
        #      - get the maximum-CU-usage in 1 iteration
        #      - if the maximum-CU-usage is less-or-equal to 85%-CU-limit, return it
        #      - divide the maximum-CU-usage on 85%-CU-limit
        #      - decrease EVM-steps on 10% if EVM-steps are equal to the last value
        #
        #   3 attempt logic is the same with 2 attempt
        #      ....
        #
        # so, it looks enough to run 5 iterations for EVM steps prediction...

        for retry in range(5):
            exec_iter_cnt = (total_step_cnt // step_cnt) + (1 if (total_step_cnt % step_cnt) else 0)
            # remove 1 iteration for finalization
            wrap_iter_cnt = max((self._ctx.wrap_iter_cnt - 1) if (not self._completed_evm_step_cnt) else 0, 0)
            iter_cnt = wrap_iter_cnt + exec_iter_cnt

            tx_list: list[SolTx] = [self._build_tx(is_finalized=True, step_cnt=step_cnt) for _ in range(iter_cnt)]

            emul_tx_list = await self._emulate_tx_list(tx_list, mult_factor=mult_factor)
            used_cu_limit = max(map(lambda x: x.meta.used_cu_limit, emul_tx_list))
            success_iter_cnt = len(filter(lambda x: not x.meta.error, emul_tx_list))
            _LOG.debug(
                "retry %d, got %d compute units for %d EVM steps per iteration, %d iterations, %d success iterations",
                retry + 1,
                used_cu_limit,
                step_cnt,
                exec_iter_cnt,
                success_iter_cnt,
            )

            if max_used_cu_limit > used_cu_limit:
                _LOG.debug("use %s EVM steps, %s iterations", step_cnt, success_iter_cnt)
                return self._IterInfo(False, step_cnt, success_iter_cnt)

            ratio = min(max_used_cu_limit / used_cu_limit, 0.9)  # decrease in 10% in any case
            new_step_cnt = max(step_cnt * ratio, step_cnt_iter)
            if new_step_cnt == step_cnt:
                break
            step_cnt = new_step_cnt

        step_cnt = self._def_evm_step_cnt
        iter_cnt = self._ctx.wrap_iter_cnt + max_iter_cnt - 1
        _LOG.debug("use default %s EVM steps, %s iterations", step_cnt, iter_cnt)
        return self._IterInfo(False, step_cnt, iter_cnt)

    def _get_def_evm_step_cnt(self) -> _IterInfo:
        step_cnt_iter = self._ctx.evm_step_cnt_per_iter
        total_step_cnt = self._ctx.total_evm_step_cnt - self._completed_evm_step_cnt + 1

        if not total_step_cnt:
            _LOG.debug("just 1 finalization iteration")
            return self._IterInfo(True, step_cnt_iter, 1)

        exec_iter_cnt = max((total_step_cnt + step_cnt_iter - 1) // step_cnt_iter, 1)
        # remove 1 iteration for finalization
        wrap_iter_cnt = max((self._ctx.wrap_iter_cnt - 1) if (not self._completed_evm_step_cnt) else 0, 0)
        iter_cnt = exec_iter_cnt + wrap_iter_cnt

        _LOG.debug(
            "%s total EVM steps, %s completed EVM steps, %s EVM steps per iteration, %s iterations",
            self._ctx.total_evm_step_cnt,
            self._completed_evm_step_cnt,
            step_cnt_iter,
            iter_cnt,
        )
        return self._IterInfo(False, step_cnt_iter, iter_cnt)

    def _get_stuck_evm_step_cnt(self) -> _IterInfo:
        _LOG.debug("just 1 finalization iteration for stuck NeonTx")
        return self._IterInfo(True, self._ctx.evm_step_cnt_per_iter, 1)

    @dataclass(frozen=True)
    class _IterInfo:
        is_finalized: bool
        step_cnt: int
        iter_cnt: int

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_stuck_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
        )
        # fmt: on

    def _build_tx(self, *, is_finalized: bool = False, step_cnt: int = 0) -> SolLegacyTx:
        step_cnt = step_cnt or self._def_evm_step_cnt
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_data_ix(is_finalized, step_cnt, uniq_idx))

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

    async def _is_finalized_holder(self) -> bool:
        holder = await self._get_holder_acct()
        if holder.status == HolderAccountStatus.Finalized:
            if holder.neon_tx_hash == self._ctx.neon_tx_hash:
                _LOG.warning("holder %s has finalized tag", holder.address)
                return True
        elif holder.status == HolderAccountStatus.Active:
            if holder.neon_tx_hash != self._ctx.neon_tx_hash:
                # strange case, because the holder was tested on the start...
                raise StuckTxError(holder)

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

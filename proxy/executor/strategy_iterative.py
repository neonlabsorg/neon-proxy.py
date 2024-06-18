from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from typing import Final, ClassVar

from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.neon_rpc.api import HolderAccountModel, HolderAccountStatus
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import (
    SolNoMoreRetriesError,
    SolCbExceededError,
    SolCbExceededCriticalError,
    SolUnknownReceiptError,
)
from common.solana_rpc.transaction_list_sender import SolTxSendState
from .errors import StuckTxError
from .strategy_base import BaseTxStrategy, SolTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from ..base.ex_api import ExecTxRespCode

_LOG = logging.getLogger(__name__)


class IterativeTxStrategy(BaseTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromData.name
    is_simple: ClassVar[bool] = False
    _cancel_name: ClassVar[str] = NeonEvmIxCode.CancelWithHash.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._completed_evm_step_cnt = 0
        self._ix_mode: NeonIxMode | None = None

    @property
    def _cu_price(self) -> int:
        # Apply priority fee only in iterative transactions
        return self._ctx.cfg.cu_price

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if await self._is_finalized_holder():
            return ExecTxRespCode.Failed

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
        holder = await self._get_holder_acct()
        if (holder.status != HolderAccountStatus.Active) or (holder.neon_tx_hash != self._ctx.neon_tx_hash):
            _LOG.debug("holder %s doesn't contain %s NeonTx", holder.address, self._ctx.neon_tx_hash)
            return ExecTxRespCode.Failed

        if await self._recheck_tx_list(self._cancel_name):
            # cancel is completed
            return ExecTxRespCode.Failed

        if await self._send_tx_list([self._build_cancel_tx()]):
            return ExecTxRespCode.Failed

        _LOG.error("no!? cancel tx")
        return None

    async def _emulate_and_send_tx_list(self) -> bool:
        if not (iter_list_info := self._get_final_iter_list_info()):
            iter_list_info = await self._get_iter_list_info()

        retry = 0
        while True:
            try:
                if iter_list_info.tx_list:
                    tx_list = iter_list_info.tx_list
                else:
                    tx_list = tuple(self._build_tx(iter_list_info.sol_tx_cfg) for _ in range(iter_list_info.iter_cnt))

                return await self._send_tx_list(tx_list)

            except SolUnknownReceiptError:
                if self._ix_mode is None:
                    _LOG.warning("unexpected error on iterative transaction, try to use accounts in writable mode")
                    self._ix_mode = NeonIxMode.Writable

                    if not (iter_list_info := self._get_final_iter_list_info()):
                        iter_list_info = await self._get_iter_list_info()

                    continue
                elif self._ix_mode == NeonIxMode.Writable:
                    _LOG.warning("unexpected error on iterative transaction, try to use ALL accounts in writable mode")
                    self._ix_mode = NeonIxMode.FullWritable
                    iter_list_info = self._get_def_iter_list_info()
                    continue
                else:
                    raise

            except SolCbExceededError:
                if (retry == 0) and (not iter_list_info.is_default):
                    _LOG.warning(
                        "error on a lack of the computational budget in iterative transactions, "
                        "try to use the default number of EVM steps"
                    )

                    retry += 1
                    iter_list_info = self._get_def_iter_list_info()
                else:
                    _LOG.warning(
                        "unexpected error on a lack of the computational budget in iterative transactions "
                        "with the the default number of EVM steps"
                    )
                    raise SolCbExceededCriticalError()

    async def _get_iter_list_info(self) -> _IterListInfo:
        _LOG.debug(
            "%d total EVM steps, %d completed EVM steps, %d EVM steps per iteration",
            self._ctx.total_evm_step_cnt,
            self._completed_evm_step_cnt,
            self._ctx.evm_step_cnt_per_iter,
        )

        step_cnt_per_iter: Final[int] = self._ctx.evm_step_cnt_per_iter
        total_step_cnt: Final[int] = self._calc_total_evm_step_cnt()
        max_exec_iter_cnt: Final[int] = self._calc_exec_iter_cnt(total_step_cnt)
        ix_mode: Final[NeonIxMode] = self._calc_ix_mode()
        wrap_iter_cnt: Final[int] = self._calc_wrap_iter_cnt(ix_mode)
        max_used_cu_limit: Final[int] = int(self._cu_limit * 0.95)  # 95% of the maximum
        mult_factor: Final[int] = max_exec_iter_cnt * 2

        # 5? attempts looks enough for evm steps calculations:
        #   1 step:
        #      - emulate the whole NeonTx in 1 iteration with the huge CU-limit
        #      - get the maximum-CU-usage for the whole NeonTx
        #      - if the maximum-CU-usage is less-or-equal to 95%-CU-limit
        #           - yes: the number of EVM steps == total available EVM steps
        #           - no:  go to the step 2
        #
        #   2 step:
        #      - divide the maximum-CU-usage on 85% of CU-limit of 1 SolTx
        #           => the number of iterations
        #      - divide the total-EVM-steps on the number of iterations
        #           => the number of EVM steps in 1 iteration
        #      - emulate the result list of iterations
        #      - find the maximum-CU-usage
        #      - if the maximum-CU-usage is less-or-equal to 95%-CU-limit:
        #           - yes: we found the number of EVM steps
        #           - no:  repeat the step 2
        #
        # Thus, it looks enough to predict EVM steps for 5 attempts...

        evm_step_cnt = max(total_step_cnt, step_cnt_per_iter)
        for retry in range(5):
            # don't try the number of step less than default per iteration
            if evm_step_cnt <= step_cnt_per_iter:
                break

            exec_iter_cnt = (total_step_cnt // evm_step_cnt) + (1 if (total_step_cnt % evm_step_cnt) > 1 else 0)
            # and as a result, the total number of iterations = the execution iterations + begin+resize iterations
            iter_cnt = exec_iter_cnt + wrap_iter_cnt

            # the possible case:
            #    1 iteration: 17'000 steps
            #    2 iteration: 17'000 steps
            #    3 iteration: 1'000 steps
            # calculate the average steps per iteration:
            #    1 iteration: 11'667
            #    2 iteration: 11'667
            #    3 iteration: 11'667
            evm_step_cnt = max(total_step_cnt // exec_iter_cnt + 1, step_cnt_per_iter)

            iter_list_info = self._IterListInfo(evm_step_cnt, iter_cnt, tuple(), ix_mode, is_default=False)
            tx_list = (self._build_tx(iter_list_info.sol_tx_cfg) for _ in range(iter_cnt))

            try:
                emul_tx_list = await self._emulate_tx_list(tuple(tx_list), mult_factor=mult_factor)
                used_cu_limit = max(map(lambda x: x.meta.used_cu_limit, emul_tx_list))
                success_iter_cnt = max(sum(1 for x in emul_tx_list if not x.meta.error), 1)
            except SolCbExceededError:
                return self._get_def_iter_list_info()

            _LOG.debug(
                "retry %d, got %d CUs for %d EVM steps per iteration -> "
                "%d execute iterations, %d success iterations",
                retry + 1,
                used_cu_limit,
                evm_step_cnt,
                exec_iter_cnt,
                success_iter_cnt,
            )

            if max_used_cu_limit > used_cu_limit:
                _LOG.debug("use %d EVM steps in %d iterations", evm_step_cnt, success_iter_cnt)
                tx_list = tuple(map(lambda x: x.tx, emul_tx_list[:success_iter_cnt]))
                return dataclasses.replace(iter_list_info, iter_cnt=success_iter_cnt, tx_list=tx_list)

            ratio = min(max_used_cu_limit / used_cu_limit, 0.9)  # decrease by 10% in any case
            new_step_cnt = max(int(evm_step_cnt * ratio), step_cnt_per_iter)
            if new_step_cnt == evm_step_cnt:
                break
            evm_step_cnt = new_step_cnt

        return self._get_def_iter_list_info()

    def _get_def_iter_list_info(self) -> _IterListInfo:
        step_cnt_per_iter = self._ctx.evm_step_cnt_per_iter
        ix_mode = self._calc_ix_mode()
        cu_limit = self._ctx.cb_prog.MaxCuLimit // 3
        cu_price = self._cu_limit // cu_limit * self._cu_price
        iter_cnt = self._calc_exec_iter_cnt() + self._calc_wrap_iter_cnt(ix_mode)

        _LOG.debug(
            "use defaults: %s EVM steps per iteration, %s iterations (%s total EVM steps, %s completed EVM steps)",
            step_cnt_per_iter,
            iter_cnt,
            self._ctx.total_evm_step_cnt,
            self._completed_evm_step_cnt,
        )

        return self._IterListInfo(step_cnt_per_iter, iter_cnt, tuple(), ix_mode, cu_price, cu_limit, is_default=True)

    def _get_final_iter_list_info(self) -> _IterListInfo | None:
        if not self._ctx.is_stuck_tx:
            total_step_cnt = self._calc_total_evm_step_cnt()
        else:
            total_step_cnt = 0

        if total_step_cnt > 1:
            return None

        _LOG.debug("just 1 finalization iteration")

        iter_cnt = 1
        step_cnt_per_iter = self._ctx.evm_step_cnt_per_iter
        ix_mode = self._ix_mode or NeonIxMode.Writable
        return self._IterListInfo(step_cnt_per_iter, iter_cnt, tuple(), ix_mode, is_default=True)

    @dataclass(frozen=True)
    class _IterListInfo:
        evm_step_cnt: int
        iter_cnt: int
        tx_list: tuple[SolTx, ...]
        ix_mode: NeonIxMode
        cu_price: int = 0
        cu_limit: int = 0
        is_default: bool = False

        @property
        def sol_tx_cfg(self) -> SolTxCfg:
            return SolTxCfg(
                evm_step_cnt=self.evm_step_cnt,
                ix_mode=self.ix_mode,
                cu_price=self.cu_price,
                cu_limit=self.cu_limit,
            )

    def _calc_total_evm_step_cnt(self) -> int:
        assert not self._ctx.is_stuck_tx
        return max(self._ctx.total_evm_step_cnt - self._completed_evm_step_cnt, 0)

    def _calc_exec_iter_cnt(self, total_step_cnt: int = 0) -> int:
        if not total_step_cnt:
            total_step_cnt = self._calc_total_evm_step_cnt()

        step_cnt_per_iter = self._ctx.evm_step_cnt_per_iter
        return max((total_step_cnt + step_cnt_per_iter - 1) // step_cnt_per_iter, 1)

    def _calc_wrap_iter_cnt(self, mode: NeonIxMode) -> int:
        # if there are NO completed evm steps,
        #   it means that we should execute the following iterations:
        #     - begin iteration
        #     - resize iterationS
        #     - but if mode is not writeable, !don't! include 1 FINALIZATION iteration

        base_iter_cnt = self._ctx.wrap_iter_cnt
        if mode == NeonIxMode.Readable:
            base_iter_cnt -= 1

        iter_cnt = max(base_iter_cnt if (not self._completed_evm_step_cnt) else 0, 0)
        return iter_cnt

    def _calc_ix_mode(self) -> NeonIxMode:
        if self._ctx.is_stuck_tx:
            return NeonIxMode.FullWritable
        elif self._ix_mode:
            return self._ix_mode

        if self._ctx.resize_iter_cnt > 0:
            _LOG.debug("NeonTx has resize iterations, force the writable mode")
            return NeonIxMode.Writable
        return NeonIxMode.Readable

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_stuck_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
            and self._validate_neon_tx_size()
        )
        # fmt: on

    def _build_tx(self, cfg: SolTxCfg = SolTxCfg.default()) -> SolLegacyTx:
        step_cnt = cfg.evm_step_cnt or self._ctx.evm_step_cnt_per_iter
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_data_ix(cfg.ix_mode, step_cnt, uniq_idx), cfg)

    def _build_cancel_tx(self) -> SolLegacyTx:
        cu_limit = self._ctx.cb_prog.DefCuLimit
        cu_price = self._ctx.cb_prog.MaxCuLimit // cu_limit * self._cu_price
        cfg = SolTxCfg(
            name=self._cancel_name,
            cu_limit=cu_limit,
            cu_price=cu_price,
        )
        return self._build_cu_tx(self._ctx.neon_prog.make_cancel_ix(), cfg)

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

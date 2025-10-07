from __future__ import annotations

import dataclasses
import itertools
import logging
from typing import Final, ClassVar, Self, Sequence

from common.neon.cancel_error import CancelErrorData
from common.neon.evm_log_decoder import NeonTxBlockInfo, NeonTxStage, NeonTxLogReturnInfo
from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.neon.transaction_decoder import SolNeonTxIxMetaInfo
from common.solana.cb_program import SolCbProg, SolCbCfg
from common.solana.errors import SolTxSizeError
from common.solana.instruction import SolTxIx
from common.solana.signer import SolSigner
from common.solana_rpc.errors import (
    SolNoMoreRetriesError,
    SolCbExceededError,
    SolCbExceededCriticalError,
    SolUnknownReceiptError,
    SolWritableError,
)
from common.utils.cached import cached_property
from .strategy_base import BaseTxStrategy, SolNeonTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from .transaction_executor_ctx import NeonExecTxState
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SolNeonIterTxCfg(SolNeonTxCfg):
    ix_mode: NeonIxMode = NeonIxMode.Unknown
    iter_cnt: int = 0
    evm_step_cnt: int = 0
    #
    _Default: ClassVar[SolNeonIterTxCfg | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._Default:
            cls._Default = cls()
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.iter_cnt == 0

    def clear(self) -> Self:
        return dataclasses.replace(self, iter_cnt=0)


class IterativeTxStrategy(BaseTxStrategy):
    Name: ClassVar[str] = NeonEvmIxCode.TxStepFromData.name
    IsSimple: ClassVar[bool] = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._uniq_idx = itertools.count()
        self._def_ix_mode = NeonIxMode.Unknown
        self._def_cu_limit = 0

    async def execute(self) -> ExecTxDoneCode:
        assert self.is_valid

        total_gas_used = -1
        fail_retry_cnt = 0

        for retry in itertools.count():
            if total_gas_used == self._ctx.gas_used:
                if (fail_retry_cnt := fail_retry_cnt + 1) > self._cfg.retry_on_fail:
                    raise SolNoMoreRetriesError()
            elif total_gas_used != -1:
                _LOG.debug(
                    "retry %d: gasUsed has changed (%d != %d)",
                    retry,
                    total_gas_used,
                    self._ctx.gas_used,
                )
                fail_retry_cnt = 0
            total_gas_used = self._ctx.gas_used

            try:
                await self._recheck_neon_tx()
                if await self._ctx.is_finalized_tx():
                    return ExecTxDoneCode.Done

                await self._exec_neon_tx()
                if await self._ctx.is_finalized_tx():
                    return ExecTxDoneCode.Done

            except BaseException as exc:
                if await self._ctx.is_finalized_tx():
                    return ExecTxDoneCode.Done
                elif isinstance(exc, SolNoMoreRetriesError):
                    pass
                raise

        return ExecTxDoneCode.Failed

    async def cancel(self, data: CancelErrorData) -> ExecTxDoneCode | None:
        ix_name: Final = NeonEvmIxCode.CancelWithHash.name

        # memo
        ix_memo: bytes = data.to_bytes()
        with self._ctx.test_mode():
            try:
                # tx size validation
                test_cfg: Final = self._init_fake_sol_neon_tx_cfg()
                test_ix: Final = self._ctx.neon_prog.make_cancel_ix(ix_memo)
                test_tx: Final = self._make_sol_neon_tx(test_cfg, test_ix)
                test_tx.validate(SolSigner.fake())  # <- there can be SolTxSizeError
            except SolTxSizeError:
                _LOG.debug("skip the cancel memo due to the Solana transaction size limit: %s:", data)
                ix_memo = bytes()

        # generate cancel tx with the default CU budget
        self._reset_to_def()
        cancel_cfg: Final = self._init_sol_neon_tx_cfg()
        cancel_ix: Final = self._ctx.neon_prog.make_cancel_ix(ix_memo)

        while True:
            if await self._ctx.is_finalized_tx():
                return ExecTxDoneCode.Done
            elif await self._ctx.recheck_sol_tx_list(ix_name):
                # cancel is completed
                return ExecTxDoneCode.Done
            elif await self._ctx.send_sol_tx(cancel_ix, cancel_cfg):
                return ExecTxDoneCode.Done

    async def done_execution(self) -> None: ...  # do nothing

    async def _recheck_neon_tx(self) -> None:
        try:
            await self._ctx.recheck_sol_tx_list(self._ix_name_list)
        finally:
            await self._find_neon_tx_status()

    def _reset_to_def(self) -> None:
        self._def_ix_mode = NeonIxMode.Unknown
        self._def_cu_limit = 0

    async def _exec_neon_tx(self) -> bool:
        self._reset_to_def()

        while True:
            try:
                if self._has_one_iter():
                    # _LOG.debug("just 1 iteration")
                    optimal_cfg = self._init_sol_neon_tx_cfg()
                elif not (optimal_cfg := await self._get_iter_list_cfg()):
                    return False

                ix_list = tuple(self._make_neon_ix(optimal_cfg) for _ in range(optimal_cfg.iter_cnt))
                return await self._send_sol_tx_list(ix_list, optimal_cfg)

            except (SolWritableError, SolUnknownReceiptError):
                if self._def_ix_mode != NeonIxMode.Writable:
                    _LOG.debug("switch to Writable mode")
                    self._def_ix_mode = NeonIxMode.Writable
                else:
                    raise

            except SolCbExceededError as exc:
                if not self._def_cu_limit:
                    self._def_cu_limit = SolCbProg.MaxCuLimit
                    _LOG.warning(
                        "fail on a lack of the computational budget in iterative transactions, "
                        "try to use the maximum (%s) CUs budget",
                        self._def_cu_limit,
                    )
                else:
                    _LOG.warning(
                        "unexpected fail on a lack of the computational budget in iterative transactions "
                        "with the the maximum (%s) CUs budget",
                        self._def_cu_limit,
                    )
                    raise SolCbExceededCriticalError(exc.cu_consumed)

    async def _get_iter_list_cfg(self) -> SolNeonIterTxCfg | None:
        evm_step_cnt_per_iter: Final[int] = self._ctx.neon_prog.EvmStepPerIter

        # 7? attempts looks enough for evm steps calculations:
        #   1 step:
        #      - emulate the whole NeonTx in 1 iteration with the huge CU-limit
        #      - get the maximum-CU-usage for the whole NeonTx
        #      - if the maximum-CU-usage is less-or-equal to max-used-CU-limit
        #           - yes: the number of EVM steps == total available EVM steps
        #           - no:  go to the step 2
        #
        #   2 step:
        #      - divide the maximum-CU-usage on 99% of CU-limit of 1 SolTx
        #           => the number of iterations
        #      - divide the total-EVM-steps on the number of iterations
        #           => the number of EVM steps in 1 iteration
        #      - emulate the result list of iterations
        #      - find the maximum-CU-usage
        #      - if the maximum-CU-usage is less-or-equal to max-used-CU-limit:
        #           - yes: we found the number of EVM steps
        #           - no:  repeat the step 2
        #
        # Thus, it looks enough to predict EVM steps for 7 attempts...

        evm_step_cnt = max(self._ctx.total_evm_step_cnt, evm_step_cnt_per_iter)
        for retry in range(7):
            # _LOG.debug(
            #     "retry %d: %d total EVM steps, %d completed EVM steps, %d EVM steps per iteration",
            #     retry,
            #     self._ctx.total_evm_step_cnt,
            #     self._ctx.completed_evm_step_cnt,
            #     evm_step_cnt,
            # )

            total_evm_step_cnt = self._ctx.total_evm_step_cnt
            exec_iter_cnt = (total_evm_step_cnt // evm_step_cnt) + (1 if (total_evm_step_cnt % evm_step_cnt) > 1 else 0)
            # and as a result, the total number of iterations = the execution iterations + begin + resize iterations
            iter_cnt = max(exec_iter_cnt + self._calc_wrap_iter_cnt(), 1)

            # the possible case:
            #    1 iteration: 17'000 steps
            #    2 iteration: 17'000 steps
            #    3 iteration: 1'000 steps
            # calculate the average steps per iteration:
            #    1 iteration: 11'667
            #    2 iteration: 11'667
            #    3 iteration: 11'667
            evm_step_cnt = max(total_evm_step_cnt // max(exec_iter_cnt, 1) + 1, evm_step_cnt_per_iter)

            base_cfg = self._init_sol_neon_tx_cfg(evm_step_cnt=evm_step_cnt, iter_cnt=iter_cnt)
            optimal_cfg = await self._calc_cu_budget(f"retry {retry}", base_cfg)
            if not optimal_cfg.is_empty:
                return optimal_cfg
            elif optimal_cfg.evm_step_cnt == evm_step_cnt:
                break
            evm_step_cnt = optimal_cfg.evm_step_cnt

        return await self._get_def_iter_list_cfg()

    async def _calc_cu_budget(self, hdr: str, base_cfg: SolNeonIterTxCfg) -> SolNeonIterTxCfg:
        evm_step_cnt_per_iter: Final[int] = self._ctx.neon_prog.EvmStepPerIter

        ix_list = tuple(self._make_neon_ix(base_cfg) for _ in range(base_cfg.iter_cnt))
        # emulate
        try:
            meta_list = await self._emulate_ix_list(ix_list)
        except SolCbExceededError:
            # _LOG.debug("%s: use default %d EVM steps")
            return base_cfg.clone(evm_step_cnt=evm_step_cnt_per_iter).clear()

        max_diff: Final[int] = 250_000
        evm_step_cnt: Final[int] = base_cfg.evm_step_cnt

        iter_cnt, cu_consumed = 0, 0
        for meta in meta_list:
            if meta.cu_consumed > base_cfg.threshold_cu_limit:
                break
            elif meta.error:
                # last iteration with error
                if not iter_cnt:
                    return base_cfg.clone(iter_cnt=1)
                break
            elif iter_cnt and abs(meta.cu_consumed - cu_consumed) > max_diff:
                break

            cu_consumed = max(cu_consumed, meta.cu_consumed)
            iter_cnt += 1

        # not enough CUs
        if not iter_cnt:
            max_cu_consumed = max(map(lambda m: m.cu_consumed, meta_list))
            ratio = min(base_cfg.threshold_cu_limit / max_cu_consumed, 0.9)  # decrease by 10% in any case
            new_evm_step_cnt = max(int(evm_step_cnt * ratio), evm_step_cnt_per_iter)

            _LOG.debug("%s: decrease EVM steps from %d to %d", hdr, evm_step_cnt, new_evm_step_cnt)
            return base_cfg.clone(evm_step_cnt=new_evm_step_cnt).clear()

        round_cu_limit = base_cfg.round_cu(cu_consumed)
        _LOG.debug(
            "%s: %s mode, %d EVM steps, %d CUs, %d iterations",
            hdr,
            base_cfg.ix_mode.name,
            evm_step_cnt,
            round_cu_limit,
            iter_cnt,
        )

        return base_cfg.clone(iter_cnt=iter_cnt, cu_limit=round_cu_limit)

    async def _emulate_ix_list(self, ix_list: Sequence[SolTxIx]) -> Sequence[EmulSolTxIxMetaModel]:
        cb_cfg = SolCbCfg(
            max_cu_limit=SolCbProg.MaxCuLimit * len(ix_list),
            heap_size=SolCbProg.MaxHeapSize,
        )
        return await self._core_api_client.emulate_sol_ix_list(cb_cfg, ix_list)

    async def _get_def_iter_list_cfg(self) -> SolNeonIterTxCfg:
        evm_step_cnt = self._ctx.neon_prog.EvmStepPerIter
        total_evm_step_cnt = self._ctx.total_evm_step_cnt

        exec_iter_cnt = max((total_evm_step_cnt + evm_step_cnt - 1) // evm_step_cnt, 1)
        iter_cnt = exec_iter_cnt + self._calc_wrap_iter_cnt()

        def_cfg = self._init_sol_neon_tx_cfg(iter_cnt=iter_cnt, evm_step_cnt=evm_step_cnt)

        _LOG.debug(
            "default: %s mode, %s EVM steps, %s iterations (%s total EVM steps, %s completed EVM steps)",
            def_cfg.ix_mode.name,
            def_cfg.evm_step_cnt,
            def_cfg.iter_cnt,
            total_evm_step_cnt,
            self._ctx.completed_evm_step_cnt,
        )
        return def_cfg

    def _has_one_iter(self) -> bool:
        if self._def_cu_limit:
            pass
        elif self._ctx.total_evm_step_cnt > 1:
            return False

        return True

    def _init_sol_neon_tx_cfg(
        self,
        /,
        evm_step_cnt: int = 0,
        iter_cnt: int = 1,
        **kwargs,
    ) -> SolNeonIterTxCfg:
        ix_mode = kwargs.pop("ix_mode", NeonIxMode.Unknown) or self._calc_ix_mode()
        cu_limit = kwargs.pop("cu_limit", self._def_cu_limit)

        tx_cfg = super()._init_sol_neon_tx_cfg(cu_limit=cu_limit, **kwargs)

        evm_step_cnt = max(evm_step_cnt, self._ctx.neon_prog.EvmStepPerIter)
        iter_cnt = max(iter_cnt, 1)

        return SolNeonIterTxCfg(**tx_cfg.to_dict(), ix_mode=ix_mode, evm_step_cnt=evm_step_cnt, iter_cnt=iter_cnt)

    def _calc_wrap_iter_cnt(self) -> int:
        ix_mode = self._calc_ix_mode()
        base_iter_cnt = 2 + self._ctx.resize_iter_cnt
        if ix_mode == NeonIxMode.Readable:
            # Finalization should be in the Writable mode
            base_iter_cnt -= 1

        # skip already finalized Begin and Resize iterations
        base_iter_cnt -= self._ctx.completed_iter_cnt

        return max(base_iter_cnt, 0)

    def _calc_ix_mode(self) -> NeonIxMode:
        if self._ctx.is_test_mode:
            return NeonIxMode.Default
        elif self._def_ix_mode != NeonIxMode.Unknown:
            ix_mode = self._def_ix_mode
            # _LOG.debug("forced ix-mode %s", self._def_ix_mode.name)
        elif not self._ctx.total_evm_step_cnt:
            ix_mode = NeonIxMode.Writable
            # _LOG.debug("no EVM steps, ix-mode %s", ix_mode.name)
        elif self._ctx.resize_iter_cnt > 0:
            ix_mode = NeonIxMode.Writable
            # _LOG.debug("resize iterations, ix-mode %s", ix_mode.name)
        else:
            ix_mode = NeonIxMode.Readable
            # _LOG.debug("default ix-mode %s", ix_mode.name)
        return ix_mode

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_skd_tx()
            and self._validate_has_chain_id()
            and self._validate_neon_tx_size()
        )
        # fmt: on

    def _make_neon_ix(self, ix_cfg: SolNeonIterTxCfg) -> SolTxIx:
        uniq_idx: Final = next(self._uniq_idx)
        return self._ctx.neon_prog.make_tx_step_from_data_ix(ix_cfg.ix_mode, ix_cfg.evm_step_cnt, uniq_idx)

    async def _find_neon_tx_status(self) -> None:
        tx_return = NeonTxLogReturnInfo.default()
        gas_used, evm_step_cnt, iter_cnt, resize_iter_cnt = 0, 0, 0, 0
        tx_block, tx_block_gas_used = NeonTxBlockInfo.default(), 0

        tx_state_list = self._ctx.get_sol_tx_state_list(self._ix_name_list)
        for tx_state in tx_state_list:
            if not tx_state.has_sol_neon_ix:
                continue
            elif tx_state.is_finalized:
                tx_return = tx_state.neon_tx_return
                _LOG.debug("found %s in %s", tx_return, tx_state.tx)
                continue
            elif tx_state.status != tx_state.status.GoodReceipt:
                continue

            iter_cnt += 1

            ix: SolNeonTxIxMetaInfo = tx_state.sol_neon_ix
            if gas_used < ix.neon_total_gas_used:
                gas_used, evm_step_cnt = ix.neon_total_gas_used, ix.neon_total_step_cnt

            if ix.neon_tx_stage == NeonTxStage.Resize:
                resize_iter_cnt += 1

            if (not ix.neon_tx_block.is_empty) and (tx_block_gas_used < ix.neon_total_gas_used):
                tx_block, tx_block_gas_used = ix.neon_tx_block, ix.neon_total_gas_used

        state = NeonExecTxState(
            gas_used=gas_used,
            evm_step_cnt=evm_step_cnt,
            iter_cnt=iter_cnt,
            resize_iter_cnt=resize_iter_cnt,
            tx_return=tx_return,
            tx_block=tx_block,
        )

        _LOG.debug(
            "NeonTx %s: status %s, slot %d, timestamp %d, iters %d, resizes %d, steps %d, gas_used %d",
            self._ctx.neon_tx_hash,
            tx_return.status_name,
            tx_block.slot,
            tx_block.timestamp,
            iter_cnt,
            resize_iter_cnt,
            evm_step_cnt,
            gas_used,
        )

        await self._ctx.set_tx_exec_state(state)

    @cached_property
    def _ix_name_list(self) -> Sequence[str]:
        return tuple([self.Name])


@alt_strategy
class AltIterativeTxStrategy(IterativeTxStrategy): ...

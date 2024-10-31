from __future__ import annotations

import dataclasses
import itertools
import logging
from dataclasses import dataclass
from typing import Final, ClassVar, Sequence

from typing_extensions import Self

from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.neon_rpc.api import HolderAccountModel
from common.solana.cb_program import SolCbProg
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import (
    SolNoMoreRetriesError,
    SolCbExceededError,
    SolCbExceededCriticalError,
    SolUnknownReceiptError,
)
from common.solana_rpc.transaction_list_sender import SolTxSendState, SolTxListSender
from common.solana_rpc.ws_client import SolWatchTxSession
from common.utils.cached import cached_property
from .errors import StuckTxError
from .holder_validator import HolderAccountValidator
from .strategy_base import BaseTxStrategy, SolTxCfg
from .strategy_stage_alt import alt_strategy
from .strategy_stage_new_account import NewAccountTxPrepStage
from ..base.ex_api import ExecTxRespCode

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolIterListCfg(SolTxCfg):
    iter_cnt: int = 0
    evm_step_cnt: int = 0

    @property
    def is_empty(self) -> bool:
        return self.iter_cnt == 0

    def clear(self) -> Self:
        return dataclasses.replace(self, iter_cnt=0)


class _HolderAccountValidator(HolderAccountValidator):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._is_stuck = False

    def mark_stuck_tx(self) -> None:
        self._is_stuck = True

    async def is_finalized(self) -> bool:
        await self.refresh()
        if (not self.is_valid) and self._holder_acct.is_active:
            # strange case, because the holder was tested on the start...
            #  it is possible if the operator-key and the holder-id are defined on two different proxies
            raise StuckTxError(self._holder_acct)

        if self._is_stuck:
            return (not self.is_valid) or self._holder_acct.is_finalized

        return self.is_valid and self._holder_acct.is_finalized


class _SolTxListSender(SolTxListSender):
    def __init__(self, *args, holder_account_validator: _HolderAccountValidator) -> None:
        super().__init__(*args)
        self._holder_acct_validator = holder_account_validator

    async def _is_done(self) -> bool:
        return await self._holder_acct_validator.is_finalized()


class IterativeTxStrategy(BaseTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromData.name
    is_simple: ClassVar[bool] = False
    _cancel_name: ClassVar[str] = NeonEvmIxCode.CancelWithHash.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._def_ix_mode = NeonIxMode.Unknown
        self._def_cu_limit = 0

    @cached_property
    def _sol_tx_list_sender(self) -> _SolTxListSender:
        return _SolTxListSender(
            self._ctx.cfg,
            self._ctx.stat_client,
            SolWatchTxSession(self._ctx.cfg, self._ctx.sol_client),
            self._ctx.sol_tx_list_signer,
            holder_account_validator=self._holder_acct_validator,
        )

    @cached_property
    def _holder_acct_validator(self) -> _HolderAccountValidator:
        return _HolderAccountValidator(self._ctx.core_api_client, self._ctx.holder_address, self._ctx.neon_tx_hash)

    @property
    def _holder_acct(self) -> HolderAccountModel:
        return self._holder_acct_validator.holder_account

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        if self._ctx.is_stuck_tx:
            self._holder_acct_validator.mark_stuck_tx()

        evm_step_cnt = -1
        fail_retry_cnt = 0

        for retry in itertools.count():
            if await self._holder_acct_validator.is_finalized():
                return ExecTxRespCode.Failed

            if evm_step_cnt == self._holder_acct.evm_step_cnt:
                fail_retry_cnt += 1
                if fail_retry_cnt > self._ctx.cfg.retry_on_fail:
                    raise SolNoMoreRetriesError()

            elif evm_step_cnt != -1:
                _LOG.debug(
                    "retry %d: the number of completed EVM steps has changed (%d != %d)",
                    retry,
                    evm_step_cnt,
                    self._holder_acct.evm_step_cnt,
                )
                fail_retry_cnt = 0

            evm_step_cnt = self._holder_acct.evm_step_cnt

            try:
                await self._recheck_tx_list(self.name)
                if (exit_code := await self._decode_neon_tx_return()) is not None:
                    return exit_code

                await self._emulate_and_send_tx_list()
                if (exit_code := await self._decode_neon_tx_return()) is not None:
                    return exit_code

            except SolNoMoreRetriesError:
                pass

    async def cancel(self) -> ExecTxRespCode | None:
        self._holder_acct_validator.mark_stuck_tx()
        if await self._holder_acct_validator.is_finalized():
            return ExecTxRespCode.Failed
        elif await self._recheck_tx_list(self._cancel_name):
            # cancel is completed
            return ExecTxRespCode.Failed

        # generate cancel tx with the default CU budget
        self._reset_to_def()

        max_cu_limit: Final[int] = SolCbProg.MaxCuLimit
        base_cfg = self._init_sol_tx_cfg(name=self._cancel_name)
        base_tx = self._build_cancel_tx(base_cfg)

        # get optimal CU budget
        optimal_cfg = await self._calc_cu_budget("cancel", base_cfg, base_tx)

        # if it is impossible to calculate the optimal CUs limit,
        #  switch to default mode with the decreased CU limit in 2 times,
        #  it should be enough because the cancel ix do only 3 steps:
        #     1. unpack holder
        #     2. return not-used gas-tokens
        #     3. mark holder as finalized
        if optimal_cfg.is_empty:
            cu_limit = max_cu_limit // 2
            _LOG.debug("fail to calculate an optimal CU budget for 'cancel', use the half (%s) CUs", cu_limit)
            optimal_cfg = await self._update_cu_price(base_cfg, cu_limit=cu_limit)

        # two attempts to cancel tx
        for retry in range(2):
            try:
                tx = self._build_cancel_tx(optimal_cfg)
                if await self._send_tx_list(tx):
                    return ExecTxRespCode.Failed

            except SolCbExceededError:
                if self._def_cu_limit:
                    raise SolCbExceededCriticalError()

                _LOG.debug(
                    "fail to execute 'cancel' with the half (%s) CUs, use the maximum (%s) CUs",
                    optimal_cfg.cu_limit,
                    self._def_cu_limit,
                )
                self._def_cu_limit = max_cu_limit
                optimal_cfg = await self._update_cu_price(base_cfg, cu_limit=max_cu_limit)

        _LOG.error("failed!? cancel tx")
        return None

    def _reset_to_def(self) -> None:
        self._def_ix_mode = NeonIxMode.Unknown
        self._def_cu_limit = 0

    async def _emulate_and_send_tx_list(self) -> bool:
        self._reset_to_def()

        while True:
            try:
                if not (iter_list_cfg := await self._get_single_iter_list_cfg()):
                    if not (iter_list_cfg := await self._get_iter_list_cfg()):
                        return False

                tx_list = tuple(self._build_tx(iter_list_cfg) for _ in range(iter_list_cfg.iter_cnt))
                return await self._send_tx_list(tx_list)

            except SolUnknownReceiptError:
                if self._def_ix_mode == NeonIxMode.Unknown:
                    _LOG.warning("unexpected fail on iterative transaction, try to use accounts in writable mode")
                    self._def_ix_mode = NeonIxMode.Writable
                elif self._def_ix_mode == NeonIxMode.Writable:
                    _LOG.warning("unexpected fail on iterative transaction, try to use ALL accounts in writable mode")
                    self._def_ix_mode = NeonIxMode.FullWritable
                else:
                    raise

            except SolCbExceededError:
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
                    raise SolCbExceededCriticalError()

    async def _get_iter_list_cfg(self) -> SolIterListCfg | None:
        evm_step_cnt_per_iter: Final[int] = self._ctx.evm_step_cnt_per_iter

        # 7? attempts looks enough for evm steps calculations:
        #   1 step:
        #      - emulate the whole NeonTx in 1 iteration with the huge CU-limit
        #      - get the maximum-CU-usage for the whole NeonTx
        #      - if the maximum-CU-usage is less-or-equal to max-used-CU-limit
        #           - yes: the number of EVM steps == total available EVM steps
        #           - no:  go to the step 2
        #
        #   2 step:
        #      - divide the maximum-CU-usage on 95% of CU-limit of 1 SolTx
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
            if await self._holder_acct_validator.is_finalized():
                return None

            _LOG.debug(
                "retry %d: %d total EVM steps, %d completed EVM steps, %d EVM steps per iteration",
                retry,
                self._ctx.total_evm_step_cnt,
                self._holder_acct.evm_step_cnt,
                evm_step_cnt,
            )

            total_evm_step_cnt = self._calc_total_evm_step_cnt()
            exec_iter_cnt = (total_evm_step_cnt // evm_step_cnt) + (1 if (total_evm_step_cnt % evm_step_cnt) > 1 else 0)

            if self._ctx.cfg.mp_send_batch_tx:
                # and as a result, the total number of iterations = the execution iterations + begin + resize iterations
                iter_cnt = exec_iter_cnt + self._calc_wrap_iter_cnt()
            else:
                iter_cnt = 1

            # the possible case:
            #    1 iteration: 17'000 steps
            #    2 iteration: 17'000 steps
            #    3 iteration: 1'000 steps
            # calculate the average steps per iteration:
            #    1 iteration: 11'667
            #    2 iteration: 11'667
            #    3 iteration: 11'667
            evm_step_cnt = max(total_evm_step_cnt // max(exec_iter_cnt, 1) + 1, evm_step_cnt_per_iter)

            base_cfg = self._init_sol_tx_cfg(evm_step_cnt=evm_step_cnt, iter_cnt=iter_cnt)
            tx_list = tuple(self._build_tx(base_cfg) for _ in range(iter_cnt))
            optimal_cfg = await self._calc_cu_budget(f"retry {retry}", base_cfg, tx_list)
            if not optimal_cfg.is_empty:
                return optimal_cfg
            elif optimal_cfg.evm_step_cnt == evm_step_cnt:
                break
            evm_step_cnt = optimal_cfg.evm_step_cnt

        return await self._get_def_iter_list_cfg()

    async def _calc_cu_budget(
        self,
        hdr: str,
        base_cfg: SolIterListCfg,
        tx_list: Sequence[SolTx] | SolTx,
    ) -> SolIterListCfg:
        evm_step_cnt_per_iter: Final[int] = self._ctx.evm_step_cnt_per_iter

        # emulate
        try:
            emul_tx_list = await self._emulate_tx_list(tx_list)
        except SolCbExceededError:
            _LOG.debug("%s: use default %d EVM steps")
            return base_cfg.update(evm_step_cnt=evm_step_cnt_per_iter).clear()

        max_cu_limit: Final[int] = SolCbProg.MaxCuLimit
        # decrease the available CU limit in Neon iteration, because Solana decreases it by default
        threshold_cu_limit: Final[int] = int(max_cu_limit * 0.95)  # 95% of the maximum
        evm_step_cnt: Final[int] = base_cfg.evm_step_cnt

        if not isinstance(emul_tx_list, Sequence):
            iter_cnt = 1
            used_cu_limit = emul_tx_list.meta.used_cu_limit
        else:
            iter_cnt = max(next((idx for idx, x in enumerate(emul_tx_list) if x.meta.error), len(emul_tx_list)), 1)
            used_cu_limit = max(map(lambda x: x.meta.used_cu_limit, emul_tx_list[:iter_cnt]))

        _LOG.debug(
            "%s: %d EVM steps, %d CUs, %d executed iterations, %d success iterations",
            hdr,
            evm_step_cnt,
            used_cu_limit,
            base_cfg.iter_cnt,
            iter_cnt,
        )

        # not enough CU limit
        if used_cu_limit > threshold_cu_limit:
            ratio = min(threshold_cu_limit / used_cu_limit, 0.9)  # decrease by 10% in any case
            new_evm_step_cnt = max(int(evm_step_cnt * ratio), evm_step_cnt_per_iter)

            _LOG.debug("%s: decrease EVM steps from %d to %d", hdr, evm_step_cnt, new_evm_step_cnt)
            return base_cfg.update(evm_step_cnt=new_evm_step_cnt).clear()

        round_coeff: Final[int] = 10_000
        inc_coeff: Final[int] = 100_000
        round_cu_limit = min((used_cu_limit // round_coeff) * round_coeff + inc_coeff, max_cu_limit)
        _LOG.debug("%s: %d EVM steps, %d CUs, %d iterations", hdr, evm_step_cnt, round_cu_limit, iter_cnt)

        return await self._update_cu_price(base_cfg.update(iter_cnt=iter_cnt), cu_limit=round_cu_limit)

    async def _get_def_iter_list_cfg(self) -> SolIterListCfg:
        cu_limit: Final[int] = SolCbProg.MaxCuLimit // 2
        evm_step_cnt: Final[int] = self._ctx.evm_step_cnt_per_iter
        total_evm_step_cnt: Final[int] = self._calc_total_evm_step_cnt()

        if self._ctx.cfg.mp_send_batch_tx:
            exec_iter_cnt = max((total_evm_step_cnt + evm_step_cnt - 1) // evm_step_cnt, 1)
            iter_cnt = exec_iter_cnt + self._calc_wrap_iter_cnt()
        else:
            iter_cnt = 1

        base_cfg = self._init_sol_tx_cfg(iter_cnt=iter_cnt, evm_step_cnt=evm_step_cnt)
        def_cfg = await self._update_cu_price(base_cfg, cu_limit=cu_limit)

        _LOG.debug(
            "default: %s EVM steps, %s CUs, %s iterations (%s total EVM steps, %s completed EVM steps)",
            def_cfg.evm_step_cnt,
            def_cfg.cu_limit,
            def_cfg.iter_cnt,
            total_evm_step_cnt,
            self._holder_acct.evm_step_cnt,
        )
        return def_cfg

    async def _get_single_iter_list_cfg(self) -> SolIterListCfg | None:
        if self._ctx.is_stuck_tx:
            pass
        elif self._def_cu_limit:
            pass
        elif self._calc_total_evm_step_cnt() > 1:
            return None

        _LOG.debug("just 1 iteration")

        base_cfg = self._init_sol_tx_cfg()
        base_tx = self._build_tx(base_cfg)

        optimal_cfg = await self._calc_cu_budget("single", base_cfg, base_tx)
        if not optimal_cfg.is_empty:
            return optimal_cfg

        # if it's impossible to optimize the CU budget, switch to default mode with the decreased CU limit in 2 times
        cu_limit = SolCbProg.MaxCuLimit // 2
        _LOG.debug("single: %s EVM steps, %s CUs", base_cfg.evm_step_cnt, cu_limit)
        optimal_cfg = await self._update_cu_price(base_cfg, cu_limit=cu_limit)
        return optimal_cfg

    def _init_sol_tx_cfg(
        self,
        *,
        evm_step_cnt: int = 0,
        iter_cnt: int = 1,
        **kwargs,
    ) -> SolIterListCfg:
        kwargs.pop("ix_mode", None)
        ix_mode = self._calc_ix_mode()

        cu_limit = kwargs.pop("cu_limit", self._def_cu_limit)
        if self._def_cu_limit:
            cu_limit = self._def_cu_limit

        tx_cfg = super()._init_sol_tx_cfg(ix_mode=ix_mode, cu_limit=cu_limit, **kwargs)

        evm_step_cnt = max(evm_step_cnt, self._ctx.evm_step_cnt_per_iter)
        iter_cnt = max(iter_cnt, 1)

        return SolIterListCfg(**tx_cfg.to_dict(), evm_step_cnt=evm_step_cnt, iter_cnt=iter_cnt)

    async def _update_cu_price(self, base_cfg: SolIterListCfg, *, cu_limit: int) -> SolIterListCfg:
        cu_limit = self._def_cu_limit or cu_limit
        cu_price = await self._calc_cu_price(base_cfg, cu_limit=cu_limit)
        return base_cfg.update(cu_limit=cu_limit, cu_price=cu_price)

    def _calc_total_evm_step_cnt(self) -> int:
        return max(self._ctx.total_evm_step_cnt - self._holder_acct.evm_step_cnt, 0)

    def _calc_wrap_iter_cnt(self) -> int:
        # if there are NO completed evm steps,
        #   it means that we should execute the following iterations:
        #     - begin iteration
        #     - resize iterationS
        #     - but if mode is NOT writeable, !don't! include 1 FINALIZATION iteration

        ix_mode = self._calc_ix_mode()
        base_iter_cnt = self._ctx.wrap_iter_cnt
        if ix_mode == NeonIxMode.Readable:
            base_iter_cnt -= 1

        iter_cnt = max(base_iter_cnt if (not self._holder_acct.evm_step_cnt) else 0, 0)
        return iter_cnt

    def _calc_ix_mode(self) -> NeonIxMode:
        if self._ctx.is_test_mode:
            return NeonIxMode.Default
        elif self._def_ix_mode != NeonIxMode.Unknown:
            ix_mode = self._def_ix_mode
            _LOG.debug("forced ix-mode %s", self._def_ix_mode.name)
        elif not self._calc_total_evm_step_cnt():
            ix_mode = NeonIxMode.Writable
            _LOG.debug("no EVM steps, ix-mode %s", ix_mode.name)
        elif self._ctx.is_stuck_tx:
            ix_mode = NeonIxMode.Readable
            _LOG.debug("stuck NeonTx, ix-mode %s", ix_mode.name)
        elif self._ctx.resize_iter_cnt > 0:
            ix_mode = NeonIxMode.Writable
            _LOG.debug("resize iterations, ix-mode %s", ix_mode.name)
        else:
            ix_mode = NeonIxMode.Readable
            _LOG.debug("default ix-mode %s", ix_mode.name)
        return ix_mode

    async def _validate(self) -> bool:
        # fmt: off
        return (
            self._validate_not_stuck_tx()
            and self._validate_no_sol_call()
            and self._validate_has_chain_id()
            and self._validate_neon_tx_size()
        )
        # fmt: on

    def _build_tx(self, tx_cfg: SolIterListCfg) -> SolLegacyTx:
        step_cnt = tx_cfg.evm_step_cnt
        uniq_idx = self._ctx.next_uniq_idx()
        prog = self._ctx.neon_prog
        return self._build_cu_tx(prog.make_tx_step_from_data_ix(tx_cfg.ix_mode, step_cnt, uniq_idx), tx_cfg)

    def _build_cancel_tx(self, tx_cfg: SolTxCfg) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_cancel_ix(), tx_cfg)

    async def _decode_neon_tx_return(self) -> ExecTxRespCode | None:
        tx_state_list = self._sol_tx_list_sender.tx_state_list
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

        if await self._holder_acct_validator.is_finalized():
            return ExecTxRespCode.Failed

        return None


@alt_strategy
class AltIterativeTxStrategy(IterativeTxStrategy):
    pass

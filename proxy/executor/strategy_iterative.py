from __future__ import annotations

import dataclasses
import itertools
import logging
from dataclasses import dataclass
from typing import Final, ClassVar, Sequence

from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.neon_rpc.api import HolderAccountModel
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


class _SolTxListSender(SolTxListSender):
    def __init__(self, *args, holder_account_validator: HolderAccountValidator) -> None:
        super().__init__(*args)
        self._holder_acct_validator = holder_account_validator
        self._stop_on_finalize = False

    def stop_on_finalize(self, value: bool) -> None:
        self._stop_on_finalize = value

    async def _is_done(self) -> bool:
        if not self._stop_on_finalize:
            return False

        holder = await self._holder_acct_validator.refresh()
        return (not self._holder_acct_validator.is_valid) or holder.is_finalized


class IterativeTxStrategy(BaseTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromData.name
    is_simple: ClassVar[bool] = False
    _cancel_name: ClassVar[str] = NeonEvmIxCode.CancelWithHash.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._prep_stage_list.append(NewAccountTxPrepStage(*args, **kwargs))
        self._def_ix_mode: NeonIxMode | None = None
        self._def_cu_limit = 0

    @property
    def _cu_price(self) -> int:
        return self._ctx.cfg.cu_price

    @cached_property
    def _sol_tx_list_sender(self) -> _SolTxListSender:
        return _SolTxListSender(
            self._ctx.cfg,
            SolWatchTxSession(self._ctx.cfg, self._ctx.sol_client),
            self._ctx.sol_tx_list_signer,
            holder_account_validator=self._holder_acct_validator,
        )

    @cached_property
    def _holder_acct_validator(self) -> HolderAccountValidator:
        return HolderAccountValidator(self._ctx.core_api_client, self._ctx.holder_address, self._ctx.neon_tx_hash)

    @property
    def _holder_acct(self) -> HolderAccountModel:
        return self._holder_acct_validator.holder_account

    async def _refresh_holder_status(self) -> None:
        await self._holder_acct_validator.refresh()
        if not self._holder_acct_validator.is_valid:
            # strange case, because the holder was tested on the start...
            #  it is possible if the operator-key and the holder-id are defined on two different proxies
            raise StuckTxError(self._holder_acct)

    async def execute(self) -> ExecTxRespCode:
        assert self.is_valid

        try:
            self._sol_tx_list_sender.stop_on_finalize(True)
            return await self._exec_impl()

        finally:
            self._sol_tx_list_sender.stop_on_finalize(False)

    async def _exec_impl(self) -> ExecTxRespCode:
        evm_step_cnt = -1
        fail_retry_cnt = 0

        for retry in itertools.count():
            await self._refresh_holder_status()
            if self._holder_acct.is_finalized:
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
        await self._refresh_holder_status()
        if not self._holder_acct.is_active:
            return ExecTxRespCode.Failed
        elif await self._recheck_tx_list(self._cancel_name):
            # cancel is completed
            return ExecTxRespCode.Failed

        try:
            self._sol_tx_list_sender.stop_on_finalize(True)
            return await self._cancel_impl()
        finally:
            self._sol_tx_list_sender.stop_on_finalize(False)

    async def _cancel_impl(self) -> ExecTxRespCode | None:
        # generate cancel tx with the default CU budget
        self._reset_to_def()
        iter_list_info = self._IterListInfo(1, 1, NeonIxMode.Default, name=self._cancel_name)
        tx_list = tuple([self._build_cancel_tx(iter_list_info.sol_tx_cfg)])

        # get optimal CU budget
        new_iter_list_info, _ = await self._calc_cu_budget("cancel", iter_list_info, tx_list)

        # if it is impossible to decrease the CU limit, switch to default mode with the decreased CU limit in 2 times
        if not new_iter_list_info:
            cu_limit = self._cu_limit // 2
            cu_price = self._cu_price * 2
            new_iter_list_info = dataclasses.replace(iter_list_info, cu_limit=cu_limit, cu_price=cu_price)

        if await self._send_tx_list([self._build_cancel_tx(new_iter_list_info.sol_tx_cfg)]):
            return ExecTxRespCode.Failed

        _LOG.error("failed!? cancel tx")
        return None

    def _reset_to_def(self) -> None:
        self._def_ix_mode = None
        self._def_cu_limit = 0

    async def _emulate_and_send_tx_list(self) -> bool:
        self._reset_to_def()

        while True:
            try:
                if not (iter_list_info := await self._get_single_iter_list_info()):
                    if not (iter_list_info := await self._get_iter_list_info()):
                        return False

                tx_list = iter_list_info.tx_list
                if not tx_list:
                    tx_cfg = iter_list_info.sol_tx_cfg
                    tx_list = tuple(self._build_tx(tx_cfg) for _ in range(iter_list_info.iter_cnt))

                return await self._send_tx_list(tx_list)

            except SolUnknownReceiptError:
                if self._def_ix_mode is None:
                    _LOG.warning("unexpected error on iterative transaction, try to use accounts in writable mode")
                    self._def_ix_mode = NeonIxMode.Writable
                elif self._def_ix_mode == NeonIxMode.Writable:
                    _LOG.warning("unexpected error on iterative transaction, try to use ALL accounts in writable mode")
                    self._def_ix_mode = NeonIxMode.FullWritable
                else:
                    raise

            except SolCbExceededError:
                if not self._def_cu_limit:
                    _LOG.warning(
                        "error on a lack of the computational budget in iterative transactions, "
                        "try to use the default number of EVM steps"
                    )
                    self._def_cu_limit = self._cu_limit
                else:
                    _LOG.warning(
                        "unexpected error on a lack of the computational budget in iterative transactions "
                        "with the the default number of EVM steps"
                    )
                    raise SolCbExceededCriticalError()

    async def _get_iter_list_info(self) -> _IterListInfo | None:
        evm_step_cnt_per_iter: Final[int] = self._ctx.evm_step_cnt_per_iter
        ix_mode: Final[NeonIxMode] = self._calc_ix_mode()

        # 5? attempts looks enough for evm steps calculations:
        #   1 step:
        #      - emulate the whole NeonTx in 1 iteration with the huge CU-limit
        #      - get the maximum-CU-usage for the whole NeonTx
        #      - if the maximum-CU-usage is less-or-equal to max-used-CU-limit
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
        #      - if the maximum-CU-usage is less-or-equal to max-used-CU-limit:
        #           - yes: we found the number of EVM steps
        #           - no:  repeat the step 2
        #
        # Thus, it looks enough to predict EVM steps for 5 attempts...

        evm_step_cnt = max(self._ctx.total_evm_step_cnt, evm_step_cnt_per_iter)
        for retry in range(5):
            # don't try if the number of step less than default per iteration
            if evm_step_cnt <= evm_step_cnt_per_iter:
                break

            await self._refresh_holder_status()
            if self._holder_acct.is_finalized:
                return None

            _LOG.debug(
                "retry %d, %d total EVM steps, %d completed EVM steps, %d EVM steps per iteration",
                retry,
                self._ctx.total_evm_step_cnt,
                self._holder_acct.evm_step_cnt,
                self._ctx.evm_step_cnt_per_iter,
            )

            total_evm_step_cnt = self._calc_total_evm_step_cnt()
            exec_iter_cnt = (total_evm_step_cnt // evm_step_cnt) + (1 if (total_evm_step_cnt % evm_step_cnt) > 1 else 0)

            if self._ctx.cfg.mp_send_batch_tx:
                # and as a result, the total number of iterations = the execution iterations + begin + resize iterations
                iter_cnt = exec_iter_cnt + self._calc_wrap_iter_cnt(ix_mode)
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
            evm_step_cnt = max(total_evm_step_cnt // exec_iter_cnt + 1, evm_step_cnt_per_iter)

            iter_list_info = self._IterListInfo(evm_step_cnt, iter_cnt, ix_mode)
            tx_list = tuple(self._build_tx(iter_list_info.sol_tx_cfg) for _ in range(iter_cnt))
            iter_list_info, new_evm_step_cnt = await self._calc_cu_budget(f"retry {retry}", iter_list_info, tx_list)
            if iter_list_info:
                return iter_list_info
            elif new_evm_step_cnt == evm_step_cnt:
                break
            evm_step_cnt = new_evm_step_cnt

        return self._get_def_iter_list_info()

    async def _calc_cu_budget(
        self,
        hdr: str,
        iter_list_info: _IterListInfo,
        tx_list: Sequence[SolTx],
    ) -> tuple[_IterListInfo | None, int]:
        # constants
        cu_limit: Final[int] = self._cu_limit
        # decrease the available CU limit in Neon iteration, because Solana decreases it by default,
        max_cu_limit: Final[int] = int(self._cu_limit * 0.95)  # 95% of the maximum
        evm_step_cnt_per_iter: Final[int] = self._ctx.evm_step_cnt_per_iter

        # emulate
        try:
            emul_tx_list = await self._emulate_tx_list(tx_list)
        except SolCbExceededError:
            return None, evm_step_cnt_per_iter

        used_cu_limit = max(map(lambda x: x.meta.used_cu_limit, emul_tx_list))
        iter_cnt = max(next((idx for idx, x in enumerate(emul_tx_list) if x.meta.error), len(emul_tx_list)), 1)
        evm_step_cnt = iter_list_info.evm_step_cnt

        _LOG.debug(
            "%s: %d EVM steps, %d max CUs, %d executed iterations, %d success iterations",
            hdr,
            evm_step_cnt,
            used_cu_limit,
            iter_list_info.iter_cnt,
            iter_cnt,
        )

        # not enough CU limit
        if used_cu_limit > max_cu_limit:
            ratio = min(max_cu_limit / used_cu_limit, 0.9)  # decrease by 10% in any case
            new_evm_step_cnt = max(int(evm_step_cnt * ratio), evm_step_cnt_per_iter)

            _LOG.debug("%s: decrease EVM steps from %d to %d", hdr, evm_step_cnt, new_evm_step_cnt)
            return None, new_evm_step_cnt

        round_coeff: Final[int] = 10_000
        inc_coeff: Final[int] = 150_000
        used_cu_limit = min((used_cu_limit // round_coeff) * round_coeff + inc_coeff, cu_limit)
        _LOG.debug("%s: %d EVM steps, %d CU limit, %d iterations", hdr, evm_step_cnt, used_cu_limit, iter_cnt)

        # if it's impossible to decrease the CU limit, use the list of already signed txs
        if used_cu_limit == cu_limit:
            tx_list = tuple(map(lambda x: x.tx, emul_tx_list[:iter_cnt]))
            return dataclasses.replace(iter_list_info, iter_cnt=iter_cnt, tx_list=tx_list), evm_step_cnt

        # decrease the cu-limit, increase the cu-price, the tx list will be signed again
        cu_price = self._cu_price * (cu_limit // used_cu_limit)
        _LOG.debug("%s: increase CU-price from %d to %d", hdr, self._cu_price, cu_price)
        optimal_info = dataclasses.replace(iter_list_info, iter_cnt=iter_cnt, cu_price=cu_price, cu_limit=used_cu_limit)
        return optimal_info, evm_step_cnt

    def _get_def_iter_list_info(self) -> _IterListInfo:
        evm_step_cnt_per_iter = self._ctx.evm_step_cnt_per_iter
        total_evm_step_cnt = self._calc_total_evm_step_cnt()
        exec_iter_cnt = max((total_evm_step_cnt + evm_step_cnt_per_iter - 1) // evm_step_cnt_per_iter, 1)
        ix_mode = self._calc_ix_mode()
        cu_limit = self._def_cu_limit or (self._cu_limit // 2)
        cu_price = self._cu_price * 2
        iter_cnt = exec_iter_cnt + self._calc_wrap_iter_cnt(ix_mode)

        _LOG.debug(
            "use defaults %s EVM steps per iteration, %s iterations (%s total EVM steps, %s completed EVM steps)",
            evm_step_cnt_per_iter,
            iter_cnt,
            self._ctx.total_evm_step_cnt,
            self._holder_acct.evm_step_cnt,
        )

        return self._IterListInfo(evm_step_cnt_per_iter, iter_cnt, ix_mode, cu_price, cu_limit, is_default=True)

    async def _get_single_iter_list_info(self) -> _IterListInfo | None:
        if self._ctx.is_stuck_tx:
            pass
        elif self._def_cu_limit:
            pass
        elif self._calc_total_evm_step_cnt() > 1:
            return None

        _LOG.debug("just 1 iteration")

        iter_cnt = 1
        evm_step_cnt = self._ctx.evm_step_cnt_per_iter
        ix_mode = self._def_ix_mode or (NeonIxMode.Readable if self._ctx.is_stuck_tx else NeonIxMode.Writable)
        iter_list_info = self._IterListInfo(evm_step_cnt, iter_cnt, ix_mode)

        if not self._def_cu_limit:
            # generate the tx list to calculate the CU limit
            tx_list = tuple(self._build_tx(iter_list_info.sol_tx_cfg) for _ in range(iter_cnt))
            new_iter_list_info, _ = await self._calc_cu_budget("single", iter_list_info, tx_list)
            if new_iter_list_info:
                return new_iter_list_info

        # if it's impossible to optimize the CU budget, switch to default mode with the decreased CU limit in 2 times
        cu_limit = self._def_cu_limit or (self._cu_limit // 2)
        cu_price = self._cu_price * 2
        return dataclasses.replace(iter_list_info, cu_limit=cu_limit, cu_price=cu_price, is_default=True)

    @dataclass(frozen=True)
    class _IterListInfo:
        evm_step_cnt: int
        iter_cnt: int
        ix_mode: NeonIxMode
        cu_price: int = 0
        cu_limit: int = 0
        tx_list: tuple[SolTx, ...] = tuple()
        is_default: bool = False
        name: str = ""

        @property
        def sol_tx_cfg(self) -> SolTxCfg:
            return SolTxCfg(
                evm_step_cnt=self.evm_step_cnt,
                ix_mode=self.ix_mode,
                cu_price=self.cu_price,
                cu_limit=self.cu_limit,
                name=self.name,
            )

    def _calc_total_evm_step_cnt(self) -> int:
        assert not self._ctx.is_stuck_tx
        return max(self._ctx.total_evm_step_cnt - self._holder_acct.evm_step_cnt, 0)

    def _calc_wrap_iter_cnt(self, mode: NeonIxMode) -> int:
        # if there are NO completed evm steps,
        #   it means that we should execute the following iterations:
        #     - begin iteration
        #     - resize iterationS
        #     - but if mode is NOT writeable, !don't! include 1 FINALIZATION iteration

        base_iter_cnt = self._ctx.wrap_iter_cnt
        if mode == NeonIxMode.Readable:
            base_iter_cnt -= 1

        iter_cnt = max(base_iter_cnt if (not self._holder_acct.evm_step_cnt) else 0, 0)
        return iter_cnt

    def _calc_ix_mode(self) -> NeonIxMode:
        if self._def_ix_mode:
            return self._def_ix_mode

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

    def _build_cancel_tx(self, cfg: SolTxCfg) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.neon_prog.make_cancel_ix(), cfg)

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

        await self._refresh_holder_status()
        if self._holder_acct.is_finalized:
            return ExecTxRespCode.Failed

        return None


@alt_strategy
class AltIterativeTxStrategy(IterativeTxStrategy):
    pass

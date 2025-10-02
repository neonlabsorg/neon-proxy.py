from __future__ import annotations

import abc
import dataclasses
import logging
from typing import Sequence, Final, ClassVar

from common.neon.cancel_error import CancelErrorData
from common.neon.cu_cost_packed import CuCostPktData
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EmulSolTxIxMetaModel
from common.solana.cb_program import SolCbProg, SolCbCfg
from common.solana.errors import SolError
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx, SolTxIx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import SolCbExceededError
from common.utils.cached import cached_property
from .server_abc import ExecutorComponent, ExecutorServerAbc
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)


class BaseTxPrepStage(ExecutorComponent, abc.ABC):
    def __init__(self, server: ExecutorServerAbc, ctx: NeonExecTxCtx):
        super().__init__(server)
        self._ctx = ctx

    @property
    def _cu_price(self) -> int:
        return self._ctx.token.simple_cu_price

    @abc.abstractmethod
    def get_tx_name_list(self) -> Sequence[str]:
        pass

    @abc.abstractmethod
    async def make_tx_list(self) -> Sequence[Sequence[SolTx]]:
        pass

    @abc.abstractmethod
    async def prep_before_exec(self) -> bool:
        pass


@dataclasses.dataclass(frozen=True)
class SolNeonTxCfg(SolCbCfg):
    pass


class BaseTxStrategy(ExecutorComponent, abc.ABC):
    name: ClassVar[str] = "UNKNOWN STRATEGY"
    is_simple: ClassVar[bool] = True

    _RoundCuLimitCoeff: Final[int] = 10_000
    _IncCuLimitCoeff: Final[int] = 25_000

    def __init__(self, server: ExecutorServerAbc, ctx: NeonExecTxCtx) -> None:
        super().__init__(server)
        self._ctx = ctx
        self._validation_error_msg: str | None = None
        self._prep_stage_list: list[BaseTxPrepStage] = list()

    @property
    def validation_error_msg(self) -> str:
        assert not self.is_valid
        return self._validation_error_msg

    @property
    def is_valid(self) -> bool:
        return self._validation_error_msg is None

    async def validate(self) -> bool:
        self._validation_error_msg = None
        try:
            if result := await self._validate():
                result = self._validate_tx_size()
            assert result == (self._validation_error_msg is None)

            return result
        except BaseException as e:
            self._validation_error_msg = str(e)
            return False

    async def prep_before_exec(self) -> bool:
        assert self.is_valid

        # recheck already sent transactions
        tx_name_list: list[str] = list()
        for stage in self._prep_stage_list:
            tx_name_list.extend(stage.get_tx_name_list())
        await self._recheck_tx_list(tuple(tx_name_list))

        # generate new transactions
        tx_list_list = await self._make_prep_tx_list()

        for tx_list in tx_list_list:
            await self._send_tx_list(tx_list)

        result = True
        for stage in self._prep_stage_list:
            result = await stage.prep_before_exec() and result
        return result

    @abc.abstractmethod
    async def execute(self) -> ExecTxDoneCode:
        pass

    async def done_execution(self) -> None: ...

    async def cancel(self, data: CancelErrorData) -> ExecTxDoneCode | None:
        return None

    def _validate_tx_size(self) -> bool:
        with self._ctx.test_mode():
            cfg = self._init_sol_neon_tx_cfg()
            neon_tx = self._make_sol_neon_tx(self._make_neon_ix(cfg), cfg)
            neon_tx.validate(SolSigner.fake())  # <- there can be SolTxSizeError
        return True

    def _validate_has_chain_id(self) -> bool:
        if self._ctx.has_chain_id:
            return True

        self._validation_error_msg = "Transaction without chain-id"
        return False

    def _validate_not_stuck_tx(self) -> bool:
        if not self._ctx.is_stuck_tx:
            return True

        self._validation_error_msg = "Stuck transaction"
        return False

    def _validate_no_sol_call(self) -> bool:
        if not self._ctx.has_external_sol_call:
            return True
        self._validation_error_msg = "Has external Solana call"
        return False

    def _validate_gas_price(self) -> bool:
        if not self._ctx.holder_tx.is_fee_less:
            return True
        self._validation_error_msg = "Fee less transaction"
        return False

    def _validate_has_sol_call(self) -> bool:
        if self._ctx.has_external_sol_call:
            return True
        self._validation_error_msg = "Doesn't have external Solana call"
        return False

    def _validate_no_resize_iter(self) -> bool:
        if self._ctx.resize_iter_cnt <= 0:
            return True
        self._validation_error_msg = f"Has {self._ctx.resize_iter_cnt} resize iterations"
        return False

    def _validate_neon_tx_size(self) -> bool:
        neon_tx_size = len(self._ctx.neon_prog.holder_msg)
        if len(self._ctx.neon_prog.holder_msg) < self._base_sol_pkt_size:
            return True
        self._validation_error_msg = f"NeonTx has size {neon_tx_size} > {self._base_sol_pkt_size}"
        return False

    def _validate_not_scheduled_tx(self) -> bool:
        if not self._ctx.is_scheduled_tx:
            return True
        self._validation_error_msg = "Scheduled transaction"
        return False

    @cached_property
    def _base_sol_pkt_size(self) -> int:
        return SolTx.PktSize - NeonProg.BaseAccountCnt * SolPubKey.KeySize

    async def _make_prep_tx_list(self) -> list[list[SolTx]]:
        tx_list_list: list[list[SolTx]] = list()

        for stage in self._prep_stage_list:
            new_tx_list_list = await stage.make_tx_list()

            while len(new_tx_list_list) > len(tx_list_list):
                tx_list_list.append(list())
            for tx_list, new_tx_list in zip(tx_list_list, new_tx_list_list):
                tx_list.extend(new_tx_list)

        return tx_list_list

    async def _recheck_tx_list(self, tx_name_list: Sequence[str] | str) -> bool:
        tx_list_sender = self._ctx.sol_tx_list_sender
        tx_list_sender.clear()

        if isinstance(tx_name_list, str):
            tx_name_list = tuple([tx_name_list])

        if not (tx_list := self._ctx.pop_sol_tx_list(tx_name_list)):
            return False

        try:
            return await tx_list_sender.recheck(tx_list)
        finally:
            self._store_sol_tx_list()

    async def _send_tx_list(self, tx_list: Sequence[SolTx] | SolTx) -> bool:
        tx_list_sender = self._ctx.sol_tx_list_sender
        tx_list_sender.clear()

        if isinstance(tx_list, SolTx):
            tx_list = tuple([tx_list])

        try:
            return await tx_list_sender.send(tx_list)
        finally:
            self._store_sol_tx_list()

    def _store_sol_tx_list(self) -> None:
        tx_state_list = self._ctx.sol_tx_list_sender.success_tx_state_list
        self._ctx.add_sol_tx_state_list(tx_state_list)

    # async def _estimate_cu_price(self) -> int:
    #     # We estimate the cu_price from the recent blocks.
    #     # Solana currently does not really take into account a writeable account list,
    #     # so the decent estimation level should be achieved by taking a weighted average from
    #     # the percentiles of compute unit prices across recent blocks.
    #     est_block_cnt = self._ctx.cfg.cu_price_estimator_block_cnt
    #     est_percentile = self._ctx.cfg.cu_price_estimator_percentile
    #     block_list = await self._ctx.db.get_block_cu_price_list(est_block_cnt)
    #
    #     return int(
    #         CuPricePercentileModel.get_weighted_percentile(
    #             est_percentile, len(block_list), map(lambda v: v.cu_price_list, block_list)
    #         )
    #     )

    def _init_sol_neon_tx_cfg(
        self,
        /,
        name: str | None = None,
        cu_limit: int = SolCbProg.MaxCuLimit,
        cu_price: int = SolCbProg.BaseCuPrice,
        heap_size: int = SolCbProg.MaxHeapSize,
    ) -> SolNeonTxCfg:
        return SolNeonTxCfg(
            name=name or self.name,
            cu_limit=cu_limit,
            cu_price=cu_price,
            heap_size=heap_size,
            round_cu_coeff=self._RoundCuLimitCoeff,
            inc_cu_coeff=self._IncCuLimitCoeff,
        )

    async def _calc_cu_price(self, cu_limit: int, rw_acct_key_list: Sequence[SolPubKey]) -> int:
        # calculate a required cu-price from the Solana statistics
        req_cu_price = await self._cu_price_client.get_cu_price(rw_acct_key_list)

        # for case of fee-less transactions
        tx = self._ctx.holder_tx
        if tx.is_fee_less:
            return req_cu_price

        # get cu-price from the gas-limit in the neon transaction
        pkt = CuCostPktData.unpack(tx.gas_limit)
        avail_cu_price = (pkt.cu_price * SolCbProg.MaxCuLimit) // cu_limit

        # get additional cu-price from the gas-price difference
        profitable_gas_price = self._ctx.token.profitable_gas_price
        tx_gas_price = self._ctx.holder_tx.effective_gas_price
        if (gas_price_diff := tx_gas_price - profitable_gas_price) > 0:
            exec_cost_diff = NeonProg.BaseGas * gas_price_diff / profitable_gas_price
            exec_diff_cu_price = int(SolCbProg.MicroLamport * exec_cost_diff / cu_limit)
            avail_cu_price += exec_diff_cu_price

        # cu_price < 10'000 isn't included in Solana Priority Queue
        cu_price = max(min(req_cu_price, avail_cu_price), SolCbProg.BaseCuPrice)

        # _LOG.debug(
        #     "use %s CU-price for %s CU-limit, %s accounts",
        #     cu_price,
        #     cu_limit,
        #     len(self._ctx.rw_account_key_list),
        # )
        return cu_price

    @staticmethod
    def _make_sol_neon_tx(ix: SolTxIx, tx_cfg: SolNeonTxCfg) -> SolLegacyTx:
        return SolCbProg.make_legacy_tx(tx_cfg, ix)

    async def _emulate_ix_list(
        self,
        ix_list: Sequence[SolTxIx] | SolTxIx,
    ) -> Sequence[EmulSolTxIxMetaModel] | EmulSolTxIxMetaModel:
        if isinstance(ix_list, SolTxIx):
            is_single_tx: Final[bool] = True
            ix_list = tuple([ix_list])
        else:
            is_single_tx: Final[bool] = False

        cu_limit = SolCbProg.MaxCuLimit * len(ix_list)
        heap_size = SolCbProg.MaxHeapSize

        try:
            meta_list = await self._core_api_client.emulate_sol_tx_list(cu_limit, heap_size, ix_list)
            return meta_list[0] if is_single_tx else meta_list
        except SolError:
            raise
        except BaseException as _exc:
            _LOG.warning("fail on emulate solana tx list")
            raise SolCbExceededError(SolCbProg.MaxCuLimit * 2)

    async def _emulate_and_send_single_tx(self, hdr: str, ix: SolTxIx, base_cfg: SolNeonTxCfg) -> bool:
        meta = await self._emulate_ix_list(ix)
        cu_consumed: Final[int] = meta.cu_consumed

        if cu_consumed > base_cfg.threshold_cu_limit:
            _LOG.warning(
                "%s: %d CUs is bigger than the upper limit %d",
                hdr,
                cu_consumed,
                base_cfg.threshold_cu_limit,
            )
            # in the case of
            #    Program <XXX> failed: instruction modified data of a read-only account
            # simulator returns the maximum cu_consumed
            #
            # raise SolCbExceededError(base_cfg.threshold_cu_limit)

        round_cu_limit = base_cfg.round_cu(cu_consumed)

        base_cfg = base_cfg.clone(cu_limit=round_cu_limit)
        return await self._send_single_tx(ix, base_cfg, self._ctx.rw_account_key_list)

    async def _send_single_tx(self, ix: SolTxIx, base_cfg: SolNeonTxCfg, rw_acct_key_list: Sequence[SolPubKey]) -> bool:
        max_cu_limit: Final[int] = SolCbProg.MaxCuLimit

        for cu_limit in (base_cfg.cu_limit, max_cu_limit):
            cu_price = await self._calc_cu_price(cu_limit, rw_acct_key_list)
            optimal_cfg = base_cfg.clone(cu_limit=cu_limit, cu_price=cu_price)
            optimal_tx = self._make_sol_neon_tx(ix, optimal_cfg)

            try:
                return await self._send_tx_list(optimal_tx)
            except SolCbExceededError:
                if cu_limit == max_cu_limit:
                    raise
                # _LOG.debug("%s: try the maximum %d CUs", max_cu_limit)
        return False

    @abc.abstractmethod
    def _make_neon_ix(self, tx_cfg: SolNeonTxCfg) -> SolTxIx:
        pass

    @abc.abstractmethod
    async def _validate(self) -> bool:
        pass

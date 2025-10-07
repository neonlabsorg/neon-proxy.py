from __future__ import annotations

import abc
import dataclasses
import logging
from typing import Sequence, Final, ClassVar

from common.neon.cancel_error import CancelErrorData
from common.neon.neon_program import NeonProg
from common.solana.cb_program import SolCbProg, SolCbCfg
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx, SolTxIx
from .server_abc import ExecutorComponent, ExecutorServerAbc
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxDoneCode

_LOG = logging.getLogger(__name__)


class BaseTxPrepStage(ExecutorComponent, abc.ABC):
    def __init__(self, server: ExecutorServerAbc, ctx: NeonExecTxCtx):
        super().__init__(server)
        self._ctx = ctx

    @property
    def ix_name_list(self):
        return self._get_ix_name_list()

    @abc.abstractmethod
    async def make_ix_list(self) -> Sequence[SolTxIx]: ...

    @abc.abstractmethod
    async def prep_execution(self) -> bool: ...

    @abc.abstractmethod
    def _get_ix_name_list(self) -> Sequence[str]: ...


@dataclasses.dataclass(frozen=True)
class SolNeonTxCfg(SolCbCfg): ...


class BaseTxStrategy(ExecutorComponent, abc.ABC):
    Name: ClassVar[str]
    IsSimple: ClassVar[bool]
    _BaseSolPktSize: Final[int] = SolTx.PktSize - NeonProg.BaseAccountCnt * SolPubKey.KeySize
    #
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

    async def prep_execution(self) -> bool:
        assert self.is_valid

        # recheck already sent transactions
        tx_name_list: list[str] = list()
        for stage in self._prep_stage_list:
            tx_name_list.extend(stage.ix_name_list)
        await self._ctx.recheck_sol_tx_list(tuple(tx_name_list))

        # generate new transactions
        ix_list: list[SolTxIx] = list()
        for stage in self._prep_stage_list:
            ix_list.extend(await stage.make_ix_list())

        cb_cfg: Final = SolCbCfg(max_priority_fee=self._ctx.max_sol_priority_fee)
        await self._ctx.send_sol_tx_list(tuple(ix_list), cb_cfg=cb_cfg)

        result = True
        for stage in self._prep_stage_list:
            result = await stage.prep_execution() and result
        return result

    def _validate_tx_size(self) -> bool:
        self._make_fake_sol_neon_tx().validate(SolSigner.fake())  # <- there can be SolTxSizeError
        return True

    def _validate_has_chain_id(self) -> bool:
        if self._ctx.has_chain_id:
            return True

        self._validation_error_msg = "Transaction without chain-id"
        return False

    def _validate_no_sol_call(self) -> bool:
        if not self._ctx.has_sol_call:
            return True

        self._validation_error_msg = "Has external Solana call"
        return False

    def _validate_has_sol_call(self) -> bool:
        if self._ctx.has_sol_call:
            return True

        self._validation_error_msg = "Doesn't have external Solana call"
        return False

    def _validate_no_resize_iter(self) -> bool:
        if self._ctx.resize_iter_cnt <= 0:
            return True

        self._validation_error_msg = f"Has {self._ctx.resize_iter_cnt} resize iterations"
        return False

    def _validate_neon_tx_size(self) -> bool:
        neon_tx_size: Final = self._ctx.neon_prog.neon_tx_size
        if neon_tx_size < self._BaseSolPktSize:
            return True

        self._validation_error_msg = f"NeonTx has size {neon_tx_size} > {self._BaseSolPktSize}"
        return False

    def _validate_not_skd_tx(self) -> bool:
        if not self._ctx.is_scheduled_tx:
            return True

        self._validation_error_msg = "Scheduled transaction"
        return False

    def _validate_skd_tx(self) -> bool:
        if self._ctx.is_scheduled_tx:
            return True

        self._validation_error_msg = "Not scheduled transaction"
        return False

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

    async def _send_sol_tx_list(self, ix_list: SolTxIx | Sequence[SolTxIx], tx_cfg: SolNeonTxCfg) -> bool:
        return await self._ctx.send_sol_tx_list(ix_list, cb_cfg=tx_cfg)

    def _init_sol_neon_tx_cfg(
        self,
        /,
        cu_limit: int = 0,
        cu_price: int = 0,
        heap_size: int = SolCbProg.MaxHeapSize,
    ) -> SolNeonTxCfg:
        return SolNeonTxCfg(
            cu_limit=cu_limit,
            cu_price=cu_price,
            heap_size=heap_size,
            round_cu_coeff=self._RoundCuLimitCoeff,
            inc_cu_coeff=self._IncCuLimitCoeff,
            max_priority_fee=self._ctx.max_sol_priority_fee,
        )

    def _init_fake_sol_neon_tx_cfg(self) -> SolNeonTxCfg:
        return self._init_sol_neon_tx_cfg(
            cu_limit=SolCbProg.MaxCuLimit,
            cu_price=SolCbProg.BaseCuPrice,
        )

    @staticmethod
    def _make_sol_neon_tx(tx_cfg: SolNeonTxCfg, ix_list: SolTxIx | Sequence[SolTxIx]) -> SolTx:
        return SolCbProg.make_legacy_tx(tx_cfg, ix_list)

    def _make_fake_sol_neon_tx(self) -> SolTx:
        with self._ctx.test_mode():
            tx_cfg: Final = self._init_fake_sol_neon_tx_cfg()
            ix: Final = self._make_neon_ix(tx_cfg)
            return self._make_sol_neon_tx(tx_cfg, ix)

    #
    # abstract methods
    #
    @abc.abstractmethod
    async def execute(self) -> ExecTxDoneCode: ...

    @abc.abstractmethod
    async def cancel(self, data: CancelErrorData) -> ExecTxDoneCode | None: ...

    @abc.abstractmethod
    async def done_execution(self) -> None: ...

    @abc.abstractmethod
    def _make_neon_ix(self, tx_cfg: SolNeonTxCfg) -> SolTxIx: ...

    @abc.abstractmethod
    async def _validate(self) -> bool: ...

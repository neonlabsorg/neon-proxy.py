from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Sequence, Final, ClassVar

from typing_extensions import Self

from common.neon.cu_price_data_model import CuPricePercentilesModel
from common.neon.neon_program import NeonIxMode, NeonProg
from common.neon.transaction_decoder import SolNeonTxMetaInfo, SolNeonTxIxMetaInfo
from common.neon_rpc.api import EmulSolTxInfo
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx, SolTxIx
from common.solana.transaction_decoder import SolTxMetaInfo
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_meta import SolRpcTxSlotInfo
from common.solana_rpc.errors import SolCbExceededError
from common.solana_rpc.transaction_list_sender import SolTxSendState, SolTxListSender
from common.solana_rpc.ws_client import SolWatchTxSession
from common.utils.cached import cached_property
from indexer.db.solana_block_db import PriorityFeePercentiles
from .transaction_executor_ctx import NeonExecTxCtx
from ..base.ex_api import ExecTxRespCode

_LOG = logging.getLogger(__name__)


class BaseTxPrepStage(abc.ABC):
    def __init__(self, ctx: NeonExecTxCtx):
        self._ctx = ctx

    @property
    def _cu_price(self) -> int:
        return self._ctx.cfg.simple_cu_price

    @abc.abstractmethod
    def get_tx_name_list(self) -> tuple[str, ...]:
        pass

    @abc.abstractmethod
    async def build_tx_list(self) -> list[list[SolTx]]:
        pass

    @abc.abstractmethod
    async def update_after_emulate(self) -> None:
        pass


@dataclass(frozen=True)
class SolTxCfg:
    name: str = ""
    evm_step_cnt: int = 0
    ix_mode: NeonIxMode = NeonIxMode.Unknown

    cu_limit: int = 0
    cu_price: int = 0
    heap_size: int = 0

    @classmethod
    def default(cls) -> Self:
        return cls()

    @classmethod
    def fake(cls) -> Self:
        return cls(
            name="Fake",
            evm_step_cnt=100,
            ix_mode=NeonIxMode.Default,
            cu_limit=100_000,
            cu_price=10_000,
            heap_size=100_000,
        )


class BaseTxStrategy(abc.ABC):
    name: ClassVar[str] = "UNKNOWN STRATEGY"
    is_simple: ClassVar[bool] = True

    def __init__(self, ctx: NeonExecTxCtx) -> None:
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

    def complete_init(self) -> None:
        assert self.is_valid

    async def prep_before_emulate(self) -> bool:
        assert self.is_valid

        # recheck already sent transactions
        tx_name_list: list[str] = list()
        for stage in self._prep_stage_list:
            tx_name_list.extend(stage.get_tx_name_list())
        await self._recheck_tx_list(tuple(tx_name_list))

        # generate new transactions
        tx_list_list = await self._build_prep_tx_list()

        has_list = False
        for tx_list in tx_list_list:
            if await self._send_tx_list(tx_list):
                has_list = True
        return has_list

    async def update_after_emulate(self) -> None:
        assert self.is_valid

        for stage in self._prep_stage_list:
            await stage.update_after_emulate()

    @property
    def has_good_sol_tx_receipt(self) -> bool:
        return self._sol_tx_list_sender.has_good_sol_tx_receipt

    @abc.abstractmethod
    async def execute(self) -> ExecTxRespCode:
        pass

    @abc.abstractmethod
    async def cancel(self) -> ExecTxRespCode | None:
        pass

    @cached_property
    def _sol_tx_list_sender(self) -> SolTxListSender:
        watch_session = SolWatchTxSession(self._ctx.cfg, self._ctx.sol_client)
        return SolTxListSender(self._ctx.cfg, self._ctx.stat_client, watch_session, self._ctx.sol_tx_list_signer)

    def _validate_tx_size(self) -> bool:
        with self._ctx.test_mode():
            self._build_tx(SolTxCfg.fake()).validate(SolSigner.fake())  # <- there will be SolTxSizeError
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
        if self._ctx.neon_tx.gas_price:
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

    @cached_property
    def _base_sol_pkt_size(self) -> int:
        return SolTx.PktSize - NeonProg.BaseAccountCnt * SolPubKey.KeySize

    async def _build_prep_tx_list(self) -> list[list[SolTx]]:
        tx_list_list: list[list[SolTx]] = list()

        for stage in self._prep_stage_list:
            new_tx_list_list = await stage.build_tx_list()

            while len(new_tx_list_list) > len(tx_list_list):
                tx_list_list.append(list())
            for tx_list, new_tx_list in zip(tx_list_list, new_tx_list_list):
                tx_list.extend(new_tx_list)

        return tx_list_list

    async def _recheck_tx_list(self, tx_name_list: tuple[str, ...] | str) -> bool:
        tx_list_sender = self._sol_tx_list_sender
        tx_list_sender.clear()

        if isinstance(tx_name_list, str):
            tx_name_list = tuple([tx_name_list])

        if not (tx_list := self._ctx.pop_sol_tx_list(tx_name_list)):
            return False

        try:
            return await tx_list_sender.recheck(tx_list)
        finally:
            self._store_sol_tx_list()

    async def _send_tx_list(self, tx_list: Sequence[SolTx]) -> bool:
        tx_list_sender = self._sol_tx_list_sender
        tx_list_sender.clear()

        try:
            return await tx_list_sender.send(tx_list)
        finally:
            self._store_sol_tx_list()

    def _store_sol_tx_list(self):
        tx_list_sender = self._sol_tx_list_sender
        self._ctx.add_sol_tx_list([tx_state.tx for tx_state in tx_list_sender.tx_state_list])

    @cached_property
    def _cu_limit(self) -> int:
        return self._ctx.cb_prog.MaxCuLimit

    async def _estimate_cu_price(self) -> int:
        # We estimate the cu_price from the recent blocks.
        # Solana currently does not really take into account writeable account list,
        # so the decent estimation level should be achieved by taking a weighted average from
        # the percentiles of compute unit prices across recent blocks.
        est_num_blocks: int = self._ctx.cfg.cu_price_estimator_num_blocks
        est_percentile: int = self._ctx.cfg.cu_price_estimator_percentile
        cu_price_list: list[PriorityFeePercentiles] = await self._ctx.db.get_recent_priority_fees(est_num_blocks)

        return int(
            CuPricePercentilesModel.get_weighted_percentile(
                est_percentile, len(cu_price_list), map(lambda v: v.cu_price_percentiles, cu_price_list)
            )
        )

    async def _init_sol_tx_cfg(
        self,
        *,
        name: str = "",
        evm_step_cnt: int = 0,
        ix_mode: NeonIxMode = NeonIxMode.Unknown,
        cu_limit: int = 0,
        cu_price: int = 0,
        heap_size: int = 0,
    ) -> SolTxCfg:
        # TODO EIP1559 churn: remove atlas.
        # if not cu_price:
        #    cu_price = await self._ctx.fee_client.get_cu_price(self._ctx.rw_account_key_list)
        cu_limit = cu_limit or self._cu_limit
        if not cu_price:
            # For legacy transactions: we estimate the cu_price from the recent blocks.
            cu_price = await self._estimate_cu_price()
            if self._ctx.tx_type == 2:
                base_fee_per_gas = self._ctx.max_fee_per_gas - self._ctx.max_priority_fee_per_gas
                assert base_fee_per_gas >= 0
                # For metamask case (base_fee_per_gas = 0), we treat it as a legacy transaction.
                # For the general case, we take into account the gas fee parameters set in Neon tx.
                if base_fee_per_gas != 0:
                    cu_price = min(
                        cu_price,
                        int(self._ctx.max_priority_fee_per_gas * 1_000_000 * 5000.0 / (base_fee_per_gas * cu_limit)),
                    )
                # cu_price should be more than 0, otherwise the Compute Budget instructions are skipped
                # and neon-evm does not digest it.
                cu_price = max(1, cu_price)

        return SolTxCfg(
            name=name or self.name,
            evm_step_cnt=evm_step_cnt or self._ctx.evm_step_cnt_per_iter,
            ix_mode=ix_mode or NeonIxMode.Default,
            cu_limit=cu_limit,
            cu_price=cu_price,
            heap_size=heap_size or self._ctx.cb_prog.MaxHeapSize,
        )

    def _build_cu_tx(self, ix: SolTxIx, tx_cfg: SolTxCfg) -> SolLegacyTx:
        cb_prog = self._ctx.cb_prog

        ix_list: list[SolTxIx] = list()

        if tx_cfg.cu_price:
            ix_list.append(cb_prog.make_cu_price_ix(tx_cfg.cu_price))
        if tx_cfg.cu_limit:
            ix_list.append(cb_prog.make_cu_limit_ix(tx_cfg.cu_limit))
        if tx_cfg.heap_size:
            ix_list.append(cb_prog.make_heap_size_ix(tx_cfg.heap_size))

        ix_list.append(ix)

        return SolLegacyTx(name=tx_cfg.name, ix_list=ix_list)

    async def _emulate_tx_list(self, tx_list: Sequence[SolTx], *, mult_factor: int = 0) -> tuple[EmulSolTxInfo, ...]:
        blockhash, _ = await self._ctx.sol_client.get_recent_blockhash(SolCommit.Finalized)
        for tx in tx_list:
            tx.set_recent_blockhash(blockhash)
        tx_list = await self._ctx.sol_tx_list_signer.sign_tx_list(tx_list)

        account_cnt_limit: Final[int] = 255  # not critical here, it's already tested on the validation step
        cu_limit = self._cu_limit * (mult_factor or len(tx_list))

        try:
            return await self._ctx.core_api_client.emulate_sol_tx_list(cu_limit, account_cnt_limit, blockhash, tx_list)
        except BaseException as exc:
            _LOG.warning("error on emulate solana tx list", exc_info=exc)
            raise SolCbExceededError()

    @staticmethod
    def _find_sol_neon_ix(tx_send_state: SolTxSendState) -> SolNeonTxIxMetaInfo | None:
        if not isinstance(tx_send_state.receipt, SolRpcTxSlotInfo):
            return None

        sol_tx = SolTxMetaInfo.from_raw(tx_send_state.slot, tx_send_state.receipt.transaction)
        sol_neon_tx = SolNeonTxMetaInfo.from_raw(sol_tx)
        return next(iter(sol_neon_tx.sol_neon_ix_list()), None)

    @abc.abstractmethod
    def _build_tx(self, tx_cfg: SolTxCfg) -> SolLegacyTx:
        pass

    @abc.abstractmethod
    async def _validate(self) -> bool:
        pass

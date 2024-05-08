from __future__ import annotations

import abc
import logging

from common.neon.transaction_decoder import SolNeonTxMetaInfo, SolNeonTxIxMetaInfo
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx, SolTxIx
from common.solana.transaction_decoder import SolTxMetaInfo
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_meta import SolRpcTxSlotInfo
from common.solana_rpc.transaction_list_sender import SolTxSendState
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


class BaseTxStrategy(abc.ABC):
    name = "UNKNOWN STRATEGY"

    def __init__(self, ctx: NeonExecTxCtx) -> None:
        self._ctx = ctx
        self._validation_error_msg: str | None = None
        self._prep_stage_list: list[BaseTxPrepStage] = list()

    @property
    def _cu_price(self) -> int:
        return self._ctx.cfg.simple_cu_price

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
        return self._ctx.sol_tx_list_sender.has_good_sol_tx_receipt

    @abc.abstractmethod
    async def execute(self) -> ExecTxRespCode:
        pass

    @abc.abstractmethod
    async def cancel(self) -> ExecTxRespCode | None:
        pass

    def _validate_tx_size(self) -> bool:
        with self._ctx.test_mode():
            self._build_tx().validate(SolSigner.fake())  # <- there will be SolTxSizeError
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
        if not self._ctx.has_external_solana_call:
            return True
        self._validation_error_msg = "Has external Solana call"
        return False

    def _validate_has_sol_call(self) -> bool:
        if self._ctx.has_external_solana_call:
            return True
        self._validation_error_msg = "Doesn't have external Solana call"
        return False

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

    async def _send_tx_list(self, tx_list: list[SolTx]) -> bool:
        tx_list_sender = self._ctx.sol_tx_list_sender
        tx_list_sender.clear()

        try:
            return await tx_list_sender.send(tx_list)
        finally:
            self._store_sol_tx_list()

    def _store_sol_tx_list(self):
        tx_list_sender = self._ctx.sol_tx_list_sender
        self._ctx.add_sol_tx_list([tx_state.tx for tx_state in tx_list_sender.tx_state_list])

    def _build_cu_tx(self, ix: SolTxIx, name: str = "") -> SolLegacyTx:
        cb_prog = self._ctx.cb_prog
        cu_price = self._cu_price

        ix_list = [
            cb_prog.make_heap_size_ix(),
            cb_prog.make_cu_limit_ix(),
        ]
        if cu_price:
            ix_list.append(cb_prog.make_cu_price_ix(cu_price))
        ix_list.append(ix)

        return SolLegacyTx(name=name or self.name, ix_list=ix_list)

    @staticmethod
    def _find_sol_neon_ix(tx_send_state: SolTxSendState) -> SolNeonTxIxMetaInfo | None:
        if not isinstance(tx_send_state.receipt, SolRpcTxSlotInfo):
            return None

        sol_tx = SolTxMetaInfo.from_raw(tx_send_state.slot, tx_send_state.receipt.transaction)
        sol_neon_tx = SolNeonTxMetaInfo.from_raw(sol_tx)
        return next(iter(sol_neon_tx.sol_neon_ix_list()), None)

    @abc.abstractmethod
    def _build_tx(self) -> SolLegacyTx:
        pass

    @abc.abstractmethod
    async def _validate(self) -> bool:
        pass

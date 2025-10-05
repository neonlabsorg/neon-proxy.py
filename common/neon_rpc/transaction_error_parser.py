import logging
import re
from typing import Sequence, Final

from .api import EmulSolTxIxMetaModel
from .errors import (
    SolNeonSkdTxUseWrongHolderError,
    SolNeonRequireResizeIterError,
    SolNeonOutOfMemoryError,
    SolNeonMissingAccountError,
    SolNeonOutOfGasError,
    SolNeonTxExecuteError,
)
from ..ethereum.errors import EthNonceTooHighError, EthNonceTooLowError
from ..neon.cancel_error import CancelErrorSource, CancelErrorData
from ..neon.evm_log_decoder import (
    NeonTxErrorLogInfo,
    NeonTxLogReturnInfo,
    NeonTxEventModel,
    NeonEvmLogDecoder,
    NeonTxLogInfo,
)
from ..neon.neon_program import NeonProg
from ..neon.transaction_decoder import SolNeonTxIxMetaInfo, SolNeonTxMetaInfo
from ..solana.log_tree_decoder import SolTxLogTreeDecoder
from ..solana.transaction_decoder import SolTxMetaInfo
from ..solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcSendTxErrorInfo,
    SolRpcTxIxFieldErrorCode,
)
from ..solana_rpc.errors import SolUnsupportedProgError
from ..solana_rpc.transaction_error_parser import SolTxErrorParser
from ..utils.cached import cached_method, cached_property

_LOG = logging.getLogger(__name__)


class SolNeonTxErrorParser(SolTxErrorParser):
    _out_of_memory_msg: Final[str] = "Program log: EVM Allocator out of memory"
    _memory_alloc_fail_msg: Final[str] = "Program log: Error: memory allocation failed, out of memory"
    _create_acct_re: Final[re.Pattern] = re.compile(
        r"Create Account: account Address { address: \w+, base: Some\(\w+\) } already in use"
    )
    _create_neon_acct_re: Final[re.Pattern] = re.compile(
        r"Program log: [a-zA-Z_/.]+:\d+ : Account \w+ - expected system owned"
    )
    # fmt: off
    _finalized_error_list: Final[Sequence[NeonTxErrorLogInfo.ErrorCode]] = tuple([
        NeonTxErrorLogInfo.ErrorCode.StorageAccountFinalized,
        NeonTxErrorLogInfo.ErrorCode.ScheduledTxAlreadyComplete,
    ])
    _done_error_list: Final[Sequence[NeonTxErrorLogInfo.ErrorCode]] = tuple([
        NeonTxErrorLogInfo.ErrorCode.ScheduledTxAlreadyInProgress,
        NeonTxErrorLogInfo.ErrorCode.TreeAccountTxInvalidStatus,
    ])
    _wrong_holder_error_list: Final[Sequence[NeonTxErrorLogInfo.ErrorCode]] = tuple([
        NeonTxErrorLogInfo.ErrorCode.NotClassicTransaction,
    ])
    _out_of_gas_error_list: Final[Sequence[NeonTxErrorLogInfo.ErrorCode]] = tuple([
        NeonTxErrorLogInfo.ErrorCode.OutOfGas,
    ])
    _missing_acct_error_list: Final[Sequence[NeonTxErrorLogInfo.ErrorCode]] = tuple([
        NeonTxErrorLogInfo.ErrorCode.AccountMissing,
    ])
    _unsupported_prog_error_list: Final[Sequence[SolRpcTxIxFieldErrorCode]] = tuple([
        SolRpcTxIxFieldErrorCode.InvalidAccountData,
        SolRpcTxIxFieldErrorCode.IncorrectProgramId,
    ])
    # fmt: on

    @cached_method
    def get_evm_error(self) -> BaseException | None:
        if self.check_if_neon_account_already_exists():
            return None
        if data := self._get_skd_tx_use_wrong_holder_error():
            return SolNeonSkdTxUseWrongHolderError(data)
        elif data := self._get_require_resize_iter_error():
            return SolNeonRequireResizeIterError(data)
        elif data := self._get_out_of_memory_error():
            return SolNeonOutOfMemoryError(data)
        elif data := self._get_missing_account_error():
            return SolNeonMissingAccountError(data)
        elif data := self._get_out_of_gas_error():
            return SolNeonOutOfGasError(data)
        elif nonce_error := self._get_nonce_error():  # struct which I decode from evm_log_decoder
            state_tx_cnt, tx_nonce = nonce_error
            if tx_nonce < state_tx_cnt:
                # the sender is unknown - should be replaced on the upper stack level
                return EthNonceTooLowError(tx_nonce, state_tx_cnt)
            else:
                return EthNonceTooHighError(tx_nonce, state_tx_cnt)
        elif self._check_if_unsupported_prog():
            return SolUnsupportedProgError()
        elif data := self._get_skd_tx_use_wrong_holder_error():
            return SolNeonSkdTxUseWrongHolderError(data)
        elif data := self._get_evm_error():
            _LOG.debug("EVM fail %s: %d - %s", self._tx, data.code, data.message)
            return SolNeonTxExecuteError(data)
        return None

    @cached_property
    def sol_neon_ix(self) -> SolNeonTxIxMetaInfo | None:
        if not isinstance(self._receipt, SolRpcTxSlotInfo):
            return None

        sol_tx = SolTxMetaInfo.from_raw(self._receipt.slot, self._receipt.transaction)
        sol_neon_tx = SolNeonTxMetaInfo.from_raw(sol_tx)
        return next(iter(sol_neon_tx.sol_neon_ix_list()), None)

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        if any(self._create_neon_acct_re.match(log_rec) for log_rec in self._evm_log_list):
            return True

        raw_log_list = self._get_log_list()
        return any(self._create_acct_re.match(log_rec) for log_rec in raw_log_list)

    @cached_method
    def get_neon_tx_return(self) -> NeonTxLogReturnInfo:
        if not self.sol_neon_ix:
            return NeonTxLogReturnInfo.default()
        elif self.sol_neon_ix.is_success and (not self.sol_neon_ix.neon_tx_return.is_empty):
            return self.sol_neon_ix.neon_tx_return

        if self._find_evm_error(self._finalized_error_list):
            return NeonTxLogReturnInfo(NeonTxEventModel.Type.Lost, 1, NeonTxLogReturnInfo.Failed)
        return NeonTxLogReturnInfo.default()

    @cached_method
    def is_done_error(self) -> bool:
        if not self.sol_neon_ix:
            return False
        return True if self._find_evm_error(self._done_error_list) else False

    def get_evm_log(self) -> NeonTxLogInfo | None:
        if self.sol_neon_ix:
            return self.sol_neon_ix.neon_log

        evm_log_list = self._evm_log_list
        return NeonEvmLogDecoder.safe_decode(evm_log_list)

    def _get_evm_error(self) -> CancelErrorData | None:
        if not self._evm_error_list:
            return None

        err_rec = self._evm_error_list[0]
        # _LOG.debug("found %s", err_rec)
        return self._fmt_error(err_rec.code, err_rec.message)

    def _get_nonce_error(self) -> tuple[int, int] | None:
        for log_rec in self._evm_error_list:
            if log_rec.code == log_rec.code.InvalidTransactionNonce:
                state_tx_cnt = int.from_bytes(log_rec.data[20:27], "little")
                tx_nonce = int.from_bytes(log_rec.data[28:35], "little")
                return int(state_tx_cnt), int(tx_nonce)
        return None

    def _get_out_of_gas_error(self) -> CancelErrorData | None:
        return self._find_evm_error(self._out_of_gas_error_list)

    def _get_missing_account_error(self) -> CancelErrorData | None:
        return self._find_evm_error(self._missing_acct_error_list)

    def _get_out_of_memory_error(self) -> CancelErrorData | None:
        log_list: Sequence[str] = self._get_log_list()
        for log_rec in log_list:
            if log_rec in (self._out_of_memory_msg, self._memory_alloc_fail_msg):
                err_msg = log_rec[idx + 2 :] if (idx := log_rec.rfind(": ")) != -1 else log_rec
                return self._fmt_error(NeonTxErrorLogInfo.ErrorCode.Custom, err_msg)
        return None

    def _get_skd_tx_use_wrong_holder_error(self) -> CancelErrorData | None:
        return self._find_evm_error(self._wrong_holder_error_list)

    @cached_method
    def _check_if_unsupported_prog(self) -> bool:
        if super()._check_if_unsupported_prog():
            return True
        elif self._get_tx_error() not in self._unsupported_prog_error_list:
            return False
        elif not (cancel_data := super()._get_error()):
            return False

        return cancel_data.address == NeonProg.ID

    def _get_require_resize_iter_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.AccountSpaceAllocationFailure])
        return self._find_evm_error(err_list)

    @cached_property
    def _evm_error_list(self) -> Sequence[NeonTxErrorLogInfo]:
        if neon_log := self.get_evm_log():
            return tuple(neon_log.tx_error_list)
        return tuple()

    @cached_property
    def _evm_log_list(self) -> Sequence[str]:
        if self.sol_neon_ix:
            return self.sol_neon_ix.log_msg_list
        elif isinstance(self._receipt, EmulSolTxIxMetaModel):
            return self._receipt.log_list
        elif not isinstance(self._receipt, SolRpcSendTxErrorInfo):
            return tuple()
        elif self._tx is None:
            return tuple()

        rpc_meta = self._receipt
        log_list: list[str] = list()
        log_state = SolTxLogTreeDecoder.decode(self._tx.message, rpc_meta, self._tx.account_key_list)
        for log_info in log_state.log_list:
            if log_info.prog_id == NeonProg.ID:
                log_list.extend(log_info.log_msg_list)
            for inner_log_info in log_info.inner_log_list:
                if inner_log_info.prog_id == NeonProg.ID:
                    log_list.extend(inner_log_info.log_msg_list)
        return tuple(log_list)

    def _find_evm_error(self, error_code_list: Sequence[NeonTxErrorLogInfo.ErrorCode]) -> CancelErrorData | None:
        for err_rec in self._evm_error_list:
            if err_rec.code in error_code_list:
                return self._fmt_error(err_rec.code, err_rec.message)
        return None

    @staticmethod
    def _fmt_error(code: NeonTxErrorLogInfo.ErrorCode, msg: str) -> CancelErrorData:
        return CancelErrorData(CancelErrorSource.NeonEVM, NeonProg.ID, code, msg)

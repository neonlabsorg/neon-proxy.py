import logging
import re
from typing import Sequence, Final

from ..neon.cancel_error import CancelErrorSource, CancelErrorData
from ..neon.evm_log_decoder import NeonTxErrorLogInfo, NeonTxLogReturnInfo, NeonTxEventModel
from ..neon.neon_program import NeonProg
from ..neon.transaction_decoder import SolNeonTxIxMetaInfo, SolNeonTxMetaInfo
from ..solana.transaction_decoder import SolTxMetaInfo
from ..solana.transaction_meta import SolRpcTxSlotInfo
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

    @cached_property
    def sol_neon_ix(self) -> SolNeonTxIxMetaInfo | None:
        if not isinstance(self._receipt, SolRpcTxSlotInfo):
            return None

        sol_tx = SolTxMetaInfo.from_raw(self._receipt.slot, self._receipt.transaction)
        sol_neon_tx = SolNeonTxMetaInfo.from_raw(sol_tx)
        return next(iter(sol_neon_tx.sol_neon_ix_list()), None)

    @cached_method
    def get_require_resize_iter_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.AccountSpaceAllocationFailure])
        return self._find_evm_error(err_list)

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        if not self.sol_neon_ix:
            return False

        elif any(self._create_neon_acct_re.match(log_rec) for log_rec in self.sol_neon_ix.log_msg_list):
            return True

        raw_log_list = self._get_log_list()
        return any(self._create_acct_re.match(log_rec) for log_rec in raw_log_list)

    @cached_method
    def get_out_of_memory_error(self) -> CancelErrorData | None:
        log_list: Sequence[str] = self._get_log_list()
        for log_rec in log_list:
            if log_rec in (self._out_of_memory_msg, self._memory_alloc_fail_msg):
                err_msg = log_rec[idx + 2 :] if (idx := log_rec.rfind(": ")) != -1 else log_rec
                return self._fmt_error(NeonTxErrorLogInfo.ErrorCode.Custom, err_msg)
        return None

    @cached_method
    def get_neon_tx_return(self) -> NeonTxLogReturnInfo:
        if not self.sol_neon_ix:
            return NeonTxLogReturnInfo.default()
        elif self.sol_neon_ix.is_success and (not self.sol_neon_ix.neon_tx_return.is_empty):
            return self.sol_neon_ix.neon_tx_return

        code = NeonTxErrorLogInfo.ErrorCode
        # fmt: off
        err_list = tuple([
            code.StorageAccountFinalized,
            code.ScheduledTxAlreadyComplete,
            code.ScheduledTxAlreadyInProgress,
            code.TreeAccountTxInvalidStatus,
        ])
        # fmt: on
        if self._find_evm_error(err_list):
            return NeonTxLogReturnInfo(NeonTxEventModel.Type.Lost, 1, NeonTxLogReturnInfo.Failed)
        return NeonTxLogReturnInfo.default()

    @cached_method
    def get_skd_tx_use_wrong_holder_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.NotClassicTransaction])
        return self._find_evm_error(err_list)

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        if not self.sol_neon_ix:
            return None

        for log_rec in self.sol_neon_ix.neon_tx_error_list:
            if log_rec.code == log_rec.code.InvalidTransactionNonce:
                state_tx_cnt = int.from_bytes(log_rec.data[20:27], "little")
                tx_nonce = int.from_bytes(log_rec.data[28:35], "little")
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def get_out_of_gas_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.OutOfGas])
        return self._find_evm_error(err_list)

    @cached_method
    def get_missing_account_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.AccountMissing])
        return self._find_evm_error(err_list)

    @cached_method
    def get_evm_error(self) -> CancelErrorData | None:
        if not self.sol_neon_ix:
            return None
        elif not self.sol_neon_ix.neon_tx_error_list:
            return None

        err_rec = self.sol_neon_ix.neon_tx_error_list[0]
        return self._fmt_error(err_rec.code, err_rec.message)

    def _find_evm_error(self, error_code_list: Sequence[NeonTxErrorLogInfo.ErrorCode]) -> CancelErrorData | None:
        if not self.sol_neon_ix:
            return None
        for err_rec in self.sol_neon_ix.neon_tx_error_list:
            if err_rec.code in error_code_list:
                return self._fmt_error(err_rec.code, err_rec.message)
        return None

    @staticmethod
    def _fmt_error(code: NeonTxErrorLogInfo.ErrorCode, msg: str) -> CancelErrorData:
        return CancelErrorData(CancelErrorSource.NeonEVM, NeonProg.ID, code, msg)

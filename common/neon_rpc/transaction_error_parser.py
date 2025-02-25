import logging
import re
from typing import Sequence, Final

from ..neon.cancel_error import CancelErrorSource, CancelErrorData
from ..neon.evm_log_decoder import NeonTxErrorLogInfo, NeonEvmLogDecoder
from ..neon.neon_program import NeonProg
from ..solana.log_tree_decoder import SolTxLogTreeDecoder
from ..solana.transaction_decoder import SolTxIxMetaInfo
from ..solana.transaction_meta import SolRpcTxSlotInfo, SolRpcSendTxErrorInfo
from ..solana_rpc.transaction_error_parser import SolTxErrorParser
from ..utils.cached import cached_method

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

    @cached_method
    def get_require_resize_iter_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.AccountSpaceAllocationFailure])
        return self._find_evm_error(err_list)

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        evm_log_list = self._get_evm_log_list()

        if any(self._create_neon_acct_re.match(log_rec) for log_rec in evm_log_list):
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
    def get_already_finalized_error(self) -> CancelErrorData | None:
        code = NeonTxErrorLogInfo.ErrorCode
        # fmt: off
        err_code_list = tuple([
            code.StorageAccountFinalized,
            code.ScheduledTxAlreadyComplete,
            code.ScheduledTxAlreadyInProgress,
            code.TreeAccountTxInvalidStatus,
        ])
        # fmt: on
        return self._find_evm_error(err_code_list)

    @cached_method
    def get_skd_tx_use_wrong_holder_error(self) -> CancelErrorData | None:
        err_list = tuple([NeonTxErrorLogInfo.ErrorCode.NotClassicTransaction])
        return self._find_evm_error(err_list)

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_list()
        for log_rec in log_list:
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
        if not (err_list := self._get_evm_error_list()):
            return None

        err_rec = err_list[0]
        return self._fmt_error(err_rec.code, err_rec.message)

    @cached_method
    def _get_evm_log_list(self) -> Sequence[str]:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            rpc_meta = self._receipt
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            rpc_meta = self._receipt.transaction.meta
        else:
            return tuple()

        log_list: list[str] = list()
        log_state = SolTxLogTreeDecoder.decode(self._tx.message, rpc_meta, self._tx.account_key_list)
        for log_info in log_state.log_list:
            if log_info.prog_id == NeonProg.ID:
                log_list.extend(log_info.log_msg_list())
            for inner_log_info in log_info.inner_log_list:
                if inner_log_info.prog_id == NeonProg.ID:
                    log_list.extend(inner_log_info.log_msg_list())
        return tuple(log_list)

    def _find_evm_error(self, error_code_list: Sequence[NeonTxErrorLogInfo.ErrorCode]) -> CancelErrorData | None:
        err_list = self._get_evm_error_list()
        for err_rec in err_list:
            if err_rec.code in error_code_list:
                return self._fmt_error(err_rec.code, err_rec.message)
        return None

    @staticmethod
    def _fmt_error(code: NeonTxErrorLogInfo.ErrorCode, msg: str) -> CancelErrorData:
        return CancelErrorData(
            CancelErrorSource.NeonEVM,
            NeonProg.ID,
            code,
            msg,
        )

    @cached_method
    def _get_evm_error_list(self) -> Sequence[NeonTxErrorLogInfo]:
        evm_log_list = self._get_evm_log_list()

        fake_tx_ix = SolTxIxMetaInfo.default()
        try:
            neon_log = NeonEvmLogDecoder().decode(fake_tx_ix, evm_log_list)
        except (BaseException,):
            return tuple()

        return tuple(neon_log.tx_error_list)

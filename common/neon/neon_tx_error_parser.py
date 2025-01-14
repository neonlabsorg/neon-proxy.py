import re
import logging
from common.utils.cached import cached_method
from common.solana_rpc.transaction_error_parser import SolTxErrorParser
from common.solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcSendTxErrorInfo,
)
from common.solana.log_tree_decoder import SolTxLogTreeDecoder
from common.neon.evm_log_decoder import NeonTxErrorLogInfo
from common.neon.evm_log_decoder import NeonEvmLogDecoder
from common.solana.signature import SolTxSig
from ..neon.neon_program import NeonProg
from common.solana.transaction_decoder import SolTxIxMetaInfo

_LOG = logging.getLogger(__name__)

class NeonTxErrorParser(SolTxErrorParser):
    code: int
    message: str

    _create_acct_re = re.compile(r"Create Account: account Address { address: \w+, base: Some\(\w+\) } already in use")
    _create_neon_acct_re = re.compile(r"Program log: [a-zA-Z_/.]+:\d+ : Account \w+ - expected system owned")

    @cached_method
    def check_if_require_resize_iter(self) -> bool:
        if self.check_if_preprocessed_error():
            if self._get_tx_ix_error() == SolRpcTxIxFieldErrorCode.ProgramFailedToComplete:
                return True

        log_list = self._get_evm_log_list()
        return any(log_rec.find(self._require_resize_iter_msg) != -1 for log_rec in reversed(log_list))

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        evm_log_list = self._get_evm_log_list()
        if any(self._create_neon_acct_re.match(log_rec) for log_rec in evm_log_list):
            return True

        raw_log_list = self._get_log_list()
        return any(self._create_acct_re.match(log_rec) for log_rec in raw_log_list)

    @cached_method
    def check_if_already_finalized(self) -> bool:
        log_list = self._get_evm_error_log_list()
        return any(log_rec.code == NeonTxErrorLogInfo.ErrorCode.StorageAccountFinalized for log_rec in log_list)

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == NeonTxErrorLogInfo.ErrorCode.InvalidTransactionNonce:
                address = log_rec.data[0:19]
                state_tx_cnt = int.from_bytes(log_rec.data[20:27])
                tx_nonce = int.from_bytes(log_rec.data[28:35])
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def get_out_of_gas_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == NeonTxErrorLogInfo.ErrorCode.OutOfGas:
                has_gas_limit = int.from_bytes(log_rec.data[0:31])
                req_gas_limit = int.from_bytes(log_rec.data[32:64])
                return int(has_gas_limit), int(req_gas_limit)
        return None

    @cached_method
    def _get_evm_log_list(self) -> tuple[str, ...]:
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

    @cached_method
    def _get_evm_error_log_list(self) -> tuple[NeonTxErrorLogInfo, ...]:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            rpc_meta = self._receipt
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            rpc_meta = self._receipt.transaction.meta
        else:
            return tuple()

        log_list: list[str] = list()
        log_state = SolTxLogTreeDecoder.decode(self._tx.message, rpc_meta, self._tx.account_key_list)

        fake_tx_ix = SolTxIxMetaInfo.default()

        error_log_list: list[NeonTxErrorLogInfo] = list()
        for log_info in log_state.log_list:
            if log_info.prog_id == NeonProg.ID:
                log_list.extend(log_info.log_msg_list())
            neon_log = NeonEvmLogDecoder().decode(fake_tx_ix, log_list)
            for error_item in neon_log.tx_error_list:
                error_log_list.append(error_item)

        return tuple(error_log_list)

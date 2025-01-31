import logging
import re
from typing import Sequence, Final

from .transaction_error_parser import SolTxErrorParser
from ..neon.evm_log_decoder import (
    NeonTxErrorLogInfo,
    NeonEvmLogDecoder,
)
from ..neon.neon_program import NeonProg
from ..solana.log_tree_decoder import SolTxLogTreeDecoder
from ..solana.pubkey import SolPubKey
from ..solana.transaction_decoder import SolTxIxMetaInfo
from ..solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcSendTxErrorInfo,
)
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
    def check_if_require_resize_iter(self) -> bool:
        log_list = self._get_evm_error_log_list()
        return any(log_rec.code == log_rec.code.AccountSpaceAllocationFailure for log_rec in log_list)

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        evm_log_list = self._get_evm_log_list()
        if any(self._create_neon_acct_re.match(log_rec) for log_rec in evm_log_list):
            return True

        raw_log_list = self._get_log_list()
        return any(self._create_acct_re.match(log_rec) for log_rec in raw_log_list)

    @cached_method
    def check_if_out_of_memory(self) -> bool:
        log_list = self._get_log_list()
        return any(log_rec in (self._out_of_memory_msg, self._memory_alloc_fail_msg) for log_rec in log_list)

    @cached_method
    def check_if_already_finalized(self) -> bool:
        log_list = self._get_evm_error_log_list()
        return any(log_rec.code == log_rec.code.StorageAccountFinalized for log_rec in log_list)

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == log_rec.code.InvalidTransactionNonce:
                state_tx_cnt = int.from_bytes(log_rec.data[20:27], "little")
                tx_nonce = int.from_bytes(log_rec.data[28:35], "little")
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def  get_out_of_gas_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == log_rec.code.OutOfGas:
                has_gas_limit = int.from_bytes(log_rec.data[0:31], "little")
                req_gas_limit = int.from_bytes(log_rec.data[32:64], "little")
                return int(has_gas_limit), int(req_gas_limit)
        return None

    @cached_method
    def get_missing_account_error(self) -> SolPubKey | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == log_rec.code.AccountMissing:
                return SolPubKey.from_raw(log_rec.data)
        return None

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

    @cached_method
    def _get_evm_error_log_list(self) -> Sequence[NeonTxErrorLogInfo]:
        evm_log_list = self._get_evm_log_list()

        fake_tx_ix = SolTxIxMetaInfo.default()
        try:
            neon_log = NeonEvmLogDecoder().decode(fake_tx_ix, evm_log_list)
        except(BaseException,):
            return tuple()

        return tuple(neon_log.tx_error_list)

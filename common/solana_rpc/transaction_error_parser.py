from __future__ import annotations

import re

from ..neon.neon_program import NeonProg
from ..solana.log_tree_decoder import SolTxLogTreeDecoder
from ..solana.transaction import SolTx
from ..solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcTxIxErrorInfo,
    SolRpcTxIxFieldErrorCode,
    SolRpcTxErrorInfo,
    SolRpcTxFieldErrorCode,
    SolRpcSendTxErrorInfo,
    SolRpcNodeUnhealthyErrorInfo,
    SolRpcTxReceiptInfo,
    SolRpcInvalidParamErrorInfo,
)
from ..utils.cached import cached_method


class SolTxErrorParser:
    _already_finalized_msg = "Program log: Transaction already finalized"
    _log_truncated_msg = "Log truncated"
    _require_resize_iter_msg = "Deployment of contract which needs more than 10kb of account space needs several"
    _cb_exceeded_msg = "exceeded CUs meter at BPF instruction"
    _out_of_memory_msg = "Program log: EVM Allocator out of memory"
    _memory_alloc_fail_msg = "Program log: Error: memory allocation failed, out of memory"

    _create_acct_re = re.compile(r"Create Account: account Address { address: \w+, base: Some\(\w+\) } already in use")
    _create_neon_acct_re = re.compile(r"Program log: [a-zA-Z_/.]+:\d+ : Account \w+ - expected system owned")
    _nonce_re = re.compile(r"Program log: Invalid Nonce, origin \w+ nonce (\d+) != Transaction nonce (\d+)")
    _out_of_gas_re = re.compile(r"Program log: Out of Gas, limit = (\d+), required = (\d+)")

    def __init__(self, tx: SolTx, receipt: SolRpcTxReceiptInfo) -> None:
        self._tx = tx
        self._receipt = receipt

    @cached_method
    def check_if_error(self) -> bool:
        if isinstance(self._receipt, (SolRpcSendTxErrorInfo, SolRpcNodeUnhealthyErrorInfo)):
            return True
        if isinstance(self._receipt, SolRpcTxSlotInfo):
            if self._receipt.transaction.meta.err:
                return True
        return False

    @cached_method
    def check_if_invalid_ix_data(self) -> bool:
        if isinstance(self._receipt, SolRpcInvalidParamErrorInfo):
            return True
        elif self._get_tx_error() == SolRpcTxFieldErrorCode.InvalidAddressLookupTableIndex:
            return True
        return self._get_tx_ix_error() == SolRpcTxIxFieldErrorCode.InvalidInstructionData

    @cached_method
    def check_if_cb_exceeded(self) -> bool:
        if self._get_tx_ix_error() == SolRpcTxIxFieldErrorCode.ComputationalBudgetExceeded:
            return True

        log_list = self._get_log_list()
        for log_rec in log_list:
            if log_rec == self._log_truncated_msg:
                return True
            elif log_rec.find(self._cb_exceeded_msg) != -1:
                return True
        return False

    @cached_method
    def check_if_out_of_memory(self) -> bool:
        log_list = self._get_log_list()
        return any(log_rec in (self._out_of_memory_msg, self._memory_alloc_fail_msg) for log_rec in log_list)

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
        log_list = self._get_evm_log_list()
        return any(log_rec == self._already_finalized_msg for log_rec in log_list)

    @cached_method
    def check_if_blockhash_notfound(self) -> bool:
        if self._receipt is None:
            return True
        return self._get_tx_error() == SolRpcTxFieldErrorCode.BlockhashNotFound

    @cached_method
    def check_if_sol_account_already_exists(self) -> bool:
        return self._get_tx_ix_error() == SolRpcTxIxFieldErrorCode.AccountAlreadyInitialized

    @cached_method
    def check_if_preprocessed_error(self) -> bool:
        return isinstance(self._receipt, SolRpcSendTxErrorInfo)

    @cached_method
    def get_num_slots_behind(self) -> int | None:
        if isinstance(self._receipt, SolRpcNodeUnhealthyErrorInfo):
            return self._receipt.num_slots_behind
        return None

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if match := self._nonce_re.match(log_rec):
                state_tx_cnt, tx_nonce = match[1], match[2]
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def get_out_of_gas_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if match := self._out_of_gas_re.match(log_rec):
                has_gas_limit, req_gas_limit = match[1], match[2]
                return int(has_gas_limit), int(req_gas_limit)
        return None

    def _get_tx_error(self) -> SolRpcTxErrorInfo | None:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            if isinstance(self._receipt.err, SolRpcTxFieldErrorCode):
                return self._receipt.err
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            if isinstance(self._receipt.transaction.meta.err, SolRpcTxErrorInfo):
                return self._receipt.transaction.meta.err
        return None

    def _get_tx_ix_error(self) -> SolRpcTxIxErrorInfo | None:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            if isinstance(self._receipt.err, SolRpcTxIxErrorInfo):
                return self._receipt.err.err
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            if isinstance(self._receipt.transaction.meta.err, SolRpcTxIxErrorInfo):
                return self._receipt.transaction.meta.err.err
        return None

    @cached_method
    def _get_log_list(self) -> tuple[str, ...]:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            return tuple(self._receipt.logs or list())
        if isinstance(self._receipt, SolRpcTxSlotInfo):
            return tuple(self._receipt.transaction.meta.log_messages or list())
        return tuple()

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

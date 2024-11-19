import re
import logging
from common.utils.cached import cached_method, cached_property
from common.solana.transaction_decoder import SolTxMetaInfo
from common.solana_rpc.transaction_error_parser import SolTxErrorParser
from common.solana.transaction_meta import (
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
from common.solana.log_tree_decoder import SolTxLogTreeDecoder
from common.neon.evm_log_decoder import SolTxIdx, NeonTxErrorLogInfo
from common.neon.evm_log_decoder import NeonEvmLogDecoder
from common.solana.signature import SolTxSig
from ..neon.neon_program import NeonProg

_LOG = logging.getLogger(__name__)

class NeonTxErrorParser(SolTxErrorParser):
    code: int
    message: str

    _create_acct_re = re.compile(r"Create Account: account Address { address: \w+, base: Some\(\w+\) } already in use")

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
                state_tx_cnt = int.from_bytes(data[20:27])
                tx_nonce = int.from_bytes(data[28:35])
                _LOG.debug("get_nonce_error: address = %s, state_tx_cnt %d , tx_nonce = %d", address, state_tx_cnt, tx_nonce)
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def get_out_of_gas_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_error_log_list()
        for log_rec in log_list:
            if log_rec.code == NeonTxErrorLogInfo.ErrorCode.OutOfGas:
                has_gas_limit = int.from_bytes(log_rec.data[0:31])
                req_gas_limit = int.from_bytes(log_recdata[32:64])
                _LOG.debug("get_out_of_gas_error: has_gas_limit = %d , req_gas_limit = %d",has_gas_limit, req_gas_limit)
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
        # TODO: add EvmLogDecoder, add parsing, error, and return that transaction is finalized

        sol_tx_idx = SolTxIdx (sol_tx_sig=SolTxSig.default(),
                               sol_ix_idx = 1,
                               sol_inner_ix_idx = None)

        error_log_list: list[NeonTxErrorLogInfo] = list()
        for log_info in log_state.log_list:
            if log_info.prog_id == NeonProg.ID:
                log_list.extend(log_info.log_msg_list())
            neon_log = NeonEvmLogDecoder().decode(sol_tx_idx, log_list)
            _LOG.debug("_get_evm_error_log_list: len(neon_log.tx_error_list) = %d , {neon_log.tx_error_list}", len(neon_log.tx_error_list), neon_log.tx_error_list)
            for error_item in neon_log.tx_error_list:
                error_log_list.append(error_item)

        _LOG.debug("_get_evm_error_log_list: len(error_log_list) = %d , {error_log_list}", len(error_log_list), error_log_list)

        return tuple(error_log_list)

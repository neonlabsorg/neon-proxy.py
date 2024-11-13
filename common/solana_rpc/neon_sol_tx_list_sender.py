import dataclasses
import logging

from common.solana_rpc.transaction_list_sender import SolTxListSender
from common.solana_rpc.transaction_list_sender import SolTxSendState
from ..solana.signature import SolTxSig
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxSlotInfo, SolRpcTxReceiptInfo
from common.neon.neon_tx_error_parser import NeonTxErrorParser
from common.solana_rpc.errors import (
    SolUnknownReceiptError,
    SolBlockhashNotFound,
    SolNeonRequireResizeIterError,
    SolCbExceededError,
    SolNoMoreRetriesError,
    SolOutOfMemoryError,
)

_LOG = logging.getLogger(__name__)

class NeonSolTxListSender(SolTxListSender):

    @dataclasses.dataclass(frozen=True)
    class _DecodeResult:
        tx_status: SolTxSendState.Status
        error: BaseException | None

    def _decode_tx_status(self, tx: SolTx, now: int, tx_receipt: SolRpcTxReceiptInfo) -> _DecodeResult:
        status = SolTxSendState.Status
        neon_tx_error_parser = NeonTxErrorParser(tx, tx_receipt)

        if not neon_tx_error_parser.check_if_preprocessed_error():
            self._commit_tx_stat_time(tx, now, is_fail=False)

        if num_slots_behind := neon_tx_error_parser.get_num_slots_behind():
            self._num_slots_behind = max(self._num_slots_behind, num_slots_behind)
            _LOG.debug("slots behind %s", self._num_slots_behind)
            return self._DecodeResult(status.NodeBehindError, None)
        elif neon_tx_error_parser.check_if_blockhash_notfound():
            if tx.recent_blockhash not in self._bad_blockhash_set:
                _LOG.debug("bad blockhash: %s", tx.recent_blockhash)
                self._bad_blockhash_set.add(tx.recent_blockhash)
            # no exception: reset blockhash on the next tx signing
            return self._DecodeResult(status.BlockHashNotFoundError, None)
        elif neon_tx_error_parser.check_if_sol_account_already_exists():
            # no exception: solana account exists - the goal is reached
            return self._DecodeResult(status.SolAccountAlreadyExistError, None)
        elif neon_tx_error_parser.check_if_already_finalized():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif neon_tx_error_parser.check_if_neon_account_already_exists():
            # no exception: neon account exists - the goal is reached
            return self._DecodeResult(status.NeonAccountAlreadyExistsError, None)
        elif neon_tx_error_parser.check_if_invalid_ix_data():
            _LOG.debug("invalid ix receipt %s: %s", tx, tx_receipt)
            return self._DecodeResult(status.InvalidIxDataError, None)
        elif neon_tx_error_parser.check_if_cb_exceeded():
            if cu_consumed := neon_tx_error_parser.cu_consumed:
                _LOG.debug("CUs consumed: %s", cu_consumed)
            return self._DecodeResult(status.CbExceededError, SolCbExceededError())
        elif neon_tx_error_parser.check_if_require_resize_iter():
            return self._DecodeResult(status.RequireResizeIterError, SolNeonRequireResizeIterError())
        elif neon_tx_error_parser.check_if_out_of_memory():
            return self._DecodeResult(status.OutOfMemoryError, SolOutOfMemoryError())

        elif gas_limit_error := neon_tx_error_parser.get_out_of_gas_error():
            gas_limit, required_gas_limit = gas_limit_error
            return self._DecodeResult(status.OutOfGasError, EthOutOfGasError(gas_limit, required_gas_limit))

        elif nonce_error := neon_tx_error_parser.get_nonce_error(): # struct which I decode from evm_log_decoder
            state_tx_cnt, tx_nonce = nonce_error
            if tx_nonce < state_tx_cnt:
                # sender is unknown - should be replaced on upper stack level
                return self._DecodeResult(status.BadNonceError, EthNonceTooLowError(tx_nonce, state_tx_cnt))
            else:
                return self._DecodeResult(status.BadNonceError, EthNonceTooHighError(tx_nonce, state_tx_cnt))

        elif neon_tx_error_parser.check_if_error():
            _LOG.debug("unknown error receipt %s: %s", tx, tx_receipt)
            # no exception: will be converted to DEFAULT EXCEPTION
            return self._DecodeResult(status.UnknownError, SolUnknownReceiptError())

        return self._DecodeResult(status.GoodReceipt, None)
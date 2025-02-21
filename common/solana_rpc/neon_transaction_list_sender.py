import logging

from .errors import SolNeonTxExecuteError
from .neon_transaction_error_parser import SolNeonTxErrorParser
from .transaction_list_sender import (
    SolTxListSender,
    SolTxSendState,
)
from ..ethereum.errors import EthNonceTooLowError, EthNonceTooHighError
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxReceiptInfo
from ..solana_rpc.errors import (
    SolNeonOutOfMemoryError,
    SolNeonRequireResizeIterError,
    SolNeonMissingAccountError,
    SolNeonSkdTxUseWrongHolderError,
    SolNeonOutOfGasError,
)

_LOG = logging.getLogger(__name__)


class SolNeonTxListSender(SolTxListSender):

    _DecodeResult = SolTxListSender._DecodeResult
    Status = SolTxSendState.Status

    def _decode_tx_status(self, tx: SolTx, now: int, tx_receipt: SolRpcTxReceiptInfo) -> _DecodeResult:
        status = SolTxSendState.Status
        neon_tx_error_parser = SolNeonTxErrorParser(tx, tx_receipt)

        if _data := neon_tx_error_parser.get_already_finalized_error():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif data := neon_tx_error_parser.get_skd_tx_use_wrong_holder_error():
            return self._DecodeResult(status.SkdTxUseWrongHolderError, SolNeonSkdTxUseWrongHolderError(data))
        elif neon_tx_error_parser.check_if_neon_account_already_exists():
            # no exception: neon account exists - the goal is reached
            return self._DecodeResult(status.NeonAccountAlreadyExistsError, None)
        elif data := neon_tx_error_parser.get_require_resize_iter_error():
            return self._DecodeResult(status.RequireResizeIterError, SolNeonRequireResizeIterError(data))
        elif data := neon_tx_error_parser.get_out_of_memory_error():
            return self._DecodeResult(status.OutOfMemoryError, SolNeonOutOfMemoryError(data))
        elif data := neon_tx_error_parser.get_missing_account_error():
            return self._DecodeResult(status.MissingAccountError, SolNeonMissingAccountError(data))
        elif data := neon_tx_error_parser.get_out_of_gas_error():
            return self._DecodeResult(status.OutOfGasError, SolNeonOutOfGasError(data))
        elif nonce_error := neon_tx_error_parser.get_nonce_error():  # struct which I decode from evm_log_decoder
            state_tx_cnt, tx_nonce = nonce_error
            if tx_nonce < state_tx_cnt:
                # sender is unknown - should be replaced on upper stack level
                return self._DecodeResult(status.BadNonceError, EthNonceTooLowError(tx_nonce, state_tx_cnt))
            else:
                return self._DecodeResult(status.BadNonceError, EthNonceTooHighError(tx_nonce, state_tx_cnt))
        elif data := neon_tx_error_parser.get_evm_error():
            _LOG.debug("EVM error %s: %d - %s", tx, data.code, data.message)
            return self._DecodeResult(status.UnknownError, SolNeonTxExecuteError(data))

        return super()._decode_tx_status(tx, now, tx_receipt)

import logging

from .sol_neon_tx_error_parser import SolNeonTxErrorParser
from .transaction_list_sender import (
    SolTxListSender,
    SolTxSendState,
)
from ..ethereum.errors import EthNonceTooLowError, EthNonceTooHighError, EthOutOfGasError
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxReceiptInfo
from ..solana_rpc.errors import (
    SolNeonOutOfMemoryError,
    SolNeonRequireResizeIterError,
    SolNeonMissingAccountError,
    SolNeonSkdTxUseWrongHolderError,
)

_LOG = logging.getLogger(__name__)


class SolNeonTxListSender(SolTxListSender):

    _DecodeResult = SolTxListSender._DecodeResult
    Status = SolTxSendState.Status

    def _decode_tx_status(self, tx: SolTx, now: int, tx_receipt: SolRpcTxReceiptInfo) -> _DecodeResult:

        status = SolTxSendState.Status
        neon_tx_error_parser = SolNeonTxErrorParser(tx, tx_receipt)

        if neon_tx_error_parser.check_if_already_finalized():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif neon_tx_error_parser.check_if_skd_tx_use_wrong_holder():
            return self._DecodeResult(status.SkdTxUseWrongHolderError, SolNeonSkdTxUseWrongHolderError())
        elif neon_tx_error_parser.check_if_neon_account_already_exists():
            # no exception: neon account exists - the goal is reached
            return self._DecodeResult(status.NeonAccountAlreadyExistsError, None)
        elif neon_tx_error_parser.check_if_require_resize_iter():
            return self._DecodeResult(status.RequireResizeIterError, SolNeonRequireResizeIterError())
        elif neon_tx_error_parser.check_if_out_of_memory():
            return self._DecodeResult(status.OutOfMemoryError, SolNeonOutOfMemoryError())

        elif acct := neon_tx_error_parser.get_missing_account_error():
            return self._DecodeResult(status.MissingAccountError, SolNeonMissingAccountError(acct))

        elif gas_limit_error := neon_tx_error_parser.get_out_of_gas_error():
            gas_limit, required_gas_limit = gas_limit_error
            return self._DecodeResult(status.OutOfGasError, EthOutOfGasError(gas_limit, required_gas_limit))

        elif nonce_error := neon_tx_error_parser.get_nonce_error():  # struct which I decode from evm_log_decoder
            state_tx_cnt, tx_nonce = nonce_error
            if tx_nonce < state_tx_cnt:
                # sender is unknown - should be replaced on upper stack level
                return self._DecodeResult(status.BadNonceError, EthNonceTooLowError(tx_nonce, state_tx_cnt))
            else:
                return self._DecodeResult(status.BadNonceError, EthNonceTooHighError(tx_nonce, state_tx_cnt))

        return super()._decode_tx_status(tx, now, tx_receipt)

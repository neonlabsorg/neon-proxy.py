import logging

from common.solana_rpc.transaction_list_sender import (
    SolTxListSender,
    SolTxListSigner,
    SolTxStatClient,
    SolWatchTxSession,
    SolTxSendState,
)
from ..solana.transaction import SolTx
from common.solana_rpc.neon_tx_error_parser import NeonTxErrorParser
from common.config.config import Config
from common.solana_rpc.errors import (
    SolUnknownReceiptError,
    SolNeonRequireResizeIterError,
    SolCbExceededError,
    SolOutOfMemoryError,
)

from common.solana.transaction_meta import SolRpcTxReceiptInfo

_LOG = logging.getLogger(__name__)

class NeonSolTxListSender(SolTxListSender):

    _DecodeResult = SolTxListSender._DecodeResult

    def _add_tx_receipt(
        self,
        tx: SolTx,
        now: int,
        tx_receipt: SolRpcTxReceiptInfo | None,
        no_receipt_status: SolTxSendState.Status,
    ):
        if not tx_receipt:
            res = self._DecodeResult(no_receipt_status, None)
        else:
            res = self._decode_tx_status(tx, now, tx_receipt)

        tx_state = SolTxSendState(
            status=res.tx_status,
            tx=tx,
            receipt=tx_receipt,
            error=res.error,
        )

        status = SolTxSendState.Status
        if tx_state.status not in (status.WaitForReceipt, status.UnknownError):
            _LOG.debug("tx status %s: %s", tx_state.tx, tx_state.status.name)

        self._tx_state_dict[tx_state.tx.sig] = tx_state
        self._tx_state_list_dict.setdefault(tx_state.status, list()).append(tx_state)

    def _decode_tx_status(self, tx: SolTx, now: int, tx_receipt: SolRpcTxReceiptInfo) -> _DecodeResult:
        status = SolTxSendState.Status

        neon_tx_error_parser = NeonTxErrorParser(tx, tx_receipt)

        if neon_tx_error_parser.check_if_already_finalized():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif neon_tx_error_parser.check_if_neon_account_already_exists():
            # no exception: neon account exists - the goal is reached
            return self._DecodeResult(status.NeonAccountAlreadyExistsError, None)

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
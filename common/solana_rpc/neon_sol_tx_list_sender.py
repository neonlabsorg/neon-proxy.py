import logging

from common.solana_rpc.transaction_list_sender import (
    SolTxListSender,
    SolTxListSigner,
    SolTxStatClient,
    SolWatchTxSession,
    SolTxSendState,
)
from ..solana.transaction import SolTx
from common.neon.neon_tx_error_parser import NeonTxErrorParser
from common.config.config import Config
from common.solana_rpc.errors import (
    SolUnknownReceiptError,
    SolNeonRequireResizeIterError,
    SolCbExceededError,
    SolOutOfMemoryError,
)

_LOG = logging.getLogger(__name__)

class NeonSolTxListSender(SolTxListSender):

    _DecodeResult = SolTxListSender._DecodeResult

    def __init__(
            self,
            cfg: Config,
            stat_client: SolTxStatClient,
            sol_session: SolWatchTxSession,
            sol_tx_signer: SolTxListSigner,
    ) -> None:
        super().__init__(cfg, stat_client, sol_session, sol_tx_signer)

def _decode_tx_status(self, tx: SolTx, now: int, tx_receipt: SolRpcTxReceiptInfo) -> _DecodeResult:
    status = SolTxSendState.Status
    neon_tx_error_parser = NeonTxErrorParser(tx, tx_receipt)

    if neon_tx_error_parser.check_if_sol_account_already_exists():
        # no exception: solana account exists - the goal is reached
        return self._DecodeResult(status.SolAccountAlreadyExistError, None)
    elif neon_tx_error_parser.check_if_already_finalized():
        # no exception: receipt exists - the goal is reached
        return self._DecodeResult(status.AlreadyFinalizedError, None)
    elif neon_tx_error_parser.check_if_neon_account_already_exists():
        # no exception: neon account exists - the goal is reached
        return self._DecodeResult(status.NeonAccountAlreadyExistsError, None)

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

    elif neon_tx_error_parser.check_if_error():
        _LOG.debug("unknown error receipt %s: %s", tx, tx_receipt)
        # no exception: will be converted to DEFAULT EXCEPTION
        return self._DecodeResult(status.UnknownError, SolUnknownReceiptError())

    return self._DecodeResult(status.GoodReceipt, None)
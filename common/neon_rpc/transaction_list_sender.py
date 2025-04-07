import dataclasses
import logging
from typing import Sequence, cast as tp_cast

from .errors import (
    SolNeonOutOfMemoryError,
    SolNeonRequireResizeIterError,
    SolNeonMissingAccountError,
    SolNeonSkdTxUseWrongHolderError,
    SolNeonOutOfGasError,
    SolNeonTxExecuteError,
)
from .transaction_error_parser import SolNeonTxErrorParser
from ..ethereum.errors import EthNonceTooLowError, EthNonceTooHighError
from ..neon.evm_log_decoder import NeonTxLogReturnInfo
from ..neon.transaction_decoder import SolNeonTxIxMetaInfo
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxReceiptInfo
from ..solana_rpc.transaction_list_sender import SolTxListSender, SolTxSendState
from ..utils.cached import cached_property, reset_cached_method

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SolNeonTxSendState(SolTxSendState):
    sol_neon_ix: SolNeonTxIxMetaInfo | None = None
    neon_tx_return: NeonTxLogReturnInfo = NeonTxLogReturnInfo.default()

    @cached_property
    def has_sol_neon_ix(self) -> bool:
        return self.sol_neon_ix is not None

    @cached_property
    def is_finalized(self) -> bool:
        return not self.neon_tx_return.is_empty


class SolNeonTxListSender(SolTxListSender):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._done_ret_cnt = 0

    def clear(self) -> None:
        super().clear()
        self._done_ret_cnt = 0
        self._get_success_tx_state_list.reset_cache(self)

    @property
    def success_tx_state_list(self) -> Sequence[SolNeonTxSendState]:
        return self._get_success_tx_state_list()

    @reset_cached_method
    def _get_success_tx_state_list(self) -> Sequence[SolNeonTxSendState]:
        # fmt: off
        return tuple([
            tp_cast(SolNeonTxSendState, tx_state)
            for tx_state in self._tx_state_dict.values()
            if tx_state.status != SolTxSendState.Status.ErrorReceipt
        ])
        # fmt: on

    def _decode_tx_status(self, tx: SolTx, tx_receipt: SolRpcTxReceiptInfo) -> SolTxSendState:
        status = SolTxSendState.Status

        tx_status: status
        tx_error: BaseException | None = None
        tx_error_parser = SolNeonTxErrorParser(tx, tx_receipt)

        if not (tx_return := tx_error_parser.get_neon_tx_return()).is_empty:
            tx_status = status.GoodReceipt
            self._done_ret_cnt += 1
        elif tx_error_parser.is_done_error():
            tx_status = status.GoodReceipt
            self._done_ret_cnt += 1
        elif data := tx_error_parser.get_skd_tx_use_wrong_holder_error():
            tx_status, tx_error = status.ErrorReceipt, SolNeonSkdTxUseWrongHolderError(data)
        elif tx_error_parser.check_if_neon_account_already_exists():
            # no exception: neon account exists - the goal is reached
            tx_status = status.GoodReceipt
        elif data := tx_error_parser.get_require_resize_iter_error():
            tx_status, tx_error = status.ErrorReceipt, SolNeonRequireResizeIterError(data)
        elif data := tx_error_parser.get_out_of_memory_error():
            tx_status, tx_error = status.ErrorReceipt, SolNeonOutOfMemoryError(data)
        elif data := tx_error_parser.get_missing_account_error():
            tx_status, tx_error = status.ErrorReceipt, SolNeonMissingAccountError(data)
        elif data := tx_error_parser.get_out_of_gas_error():
            tx_status, tx_error = status.ErrorReceipt, SolNeonOutOfGasError(data)
        elif nonce_error := tx_error_parser.get_nonce_error():  # struct which I decode from evm_log_decoder
            state_tx_cnt, tx_nonce = nonce_error
            if tx_nonce < state_tx_cnt:
                # sender is unknown - should be replaced on upper stack level
                tx_status, tx_error = status.ErrorReceipt, EthNonceTooLowError(tx_nonce, state_tx_cnt)
            else:
                tx_status, tx_error = status.ErrorReceipt, EthNonceTooHighError(tx_nonce, state_tx_cnt)
        elif data := tx_error_parser.get_evm_error():
            _LOG.debug("EVM fail %s: %d - %s", tx, data.code, data.message)
            tx_status, tx_error = status.ErrorReceipt, SolNeonTxExecuteError(data)
        else:
            tx_state = super()._decode_tx_status(tx, tx_receipt)
            tx_status, tx_error = tx_state.status, tx_state.error

        return SolNeonTxSendState(tx_status, tx, tx_receipt, tx_error, tx_error_parser.sol_neon_ix, tx_return)

    @classmethod
    def _empty_tx_status(cls, tx: SolTx, tx_status: SolTxSendState.Status) -> SolNeonTxSendState:
        return SolNeonTxSendState(tx_status, tx, None, None)

    def _is_done(self) -> bool:
        return self._done_ret_cnt > 0

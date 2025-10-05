import dataclasses
from typing import Sequence, cast as tp_cast

from .transaction_error_parser import SolNeonTxErrorParser
from ..config.config import Config
from ..neon.evm_log_decoder import NeonTxLogReturnInfo
from ..neon.transaction_decoder import SolNeonTxIxMetaInfo
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxReceiptInfo
from ..solana_rpc.client import SolClient
from ..solana_rpc.transaction_list_sender import SolTxListSender, SolTxSendState, SolTxListSigner
from ..solana_rpc.transaction_list_sender_stat import SolTxStatClient
from ..utils.cached import cached_property, reset_cached_method


# _LOG = logging.getLogger(__name__)


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
    def __init__(self,
        cfg: Config,
        sol_client: SolClient,
        sol_tx_signer: SolTxListSigner,
        stat_client: SolTxStatClient
    ) -> None:
        super().__init__(cfg, sol_client, sol_tx_signer, stat_client)
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
        elif tx_error_parser.check_if_neon_account_already_exists():
            # no exception: the neon account exists - the goal is reached
            tx_status = status.GoodReceipt
        elif tx_error := tx_error_parser.get_evm_error():
            tx_status = status.ErrorReceipt
        else:
            tx_state = super()._decode_tx_status(tx, tx_receipt)
            tx_status, tx_error = tx_state.status, tx_state.error

        # if tx_status == status.ErrorReceipt:
        #     _LOG.debug("Error receipt: %s", tx_receipt)

        return SolNeonTxSendState(tx_status, tx, tx_receipt, tx_error, tx_error_parser.sol_neon_ix, tx_return)

    @classmethod
    def _empty_tx_status(cls, tx: SolTx, tx_status: SolTxSendState.Status) -> SolNeonTxSendState:
        return SolNeonTxSendState(tx_status, tx, None, None)

    def _is_done(self) -> bool:
        return self._done_ret_cnt > 0

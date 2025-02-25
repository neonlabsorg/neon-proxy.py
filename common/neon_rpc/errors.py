from ..neon.cancel_error import CancelErrorData, CancelErrorSource
from ..neon.evm_log_decoder import NeonTxErrorLogInfo
from ..neon.neon_program import NeonProg
from ..neon.transaction_model import NeonSkdTxStatus
from ..solana_rpc.errors import SolTxExecuteError


class SolNeonTxExecuteError(SolTxExecuteError):
    pass


class SolNeonRequireResizeIterError(SolNeonTxExecuteError):
    pass


class SolNeonSkdTxError(SolNeonTxExecuteError):
    pass


class SolNeonSkdTxUseWrongHolderError(SolNeonSkdTxError):
    @property
    def message(self) -> str:
        return "NeonSkdTx use wrong holder"


class SolNeonSkdTxWrongStateError(SolNeonSkdTxError):
    def __init__(self, status: NeonSkdTxStatus) -> None:
        msg = f"NeonSkdTx has a wrong state {status.value}"
        super().__init__(
            CancelErrorData(
                CancelErrorSource.NeonEVM,
                NeonProg.ID,
                NeonTxErrorLogInfo.ErrorCode.Custom,
                msg,
            )
        )
        self._msg = msg

    @property
    def message(self) -> str:
        return self._msg


class SolNeonOutOfMemoryError(SolNeonTxExecuteError):
    pass


class SolNeonOutOfGasError(SolNeonTxExecuteError):
    pass


class SolNeonMissingAccountError(SolNeonTxExecuteError):
    pass

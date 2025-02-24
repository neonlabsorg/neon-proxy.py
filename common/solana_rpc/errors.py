from __future__ import annotations

from ..neon.cancel_error import CancelErrorData, CancelErrorSource, ProxyCancelErrorCode
from ..neon.evm_log_decoder import NeonTxErrorLogInfo
from ..neon.transaction_model import NeonSkdTxStatus
from ..solana.errors import SolError
from ..solana.transaction_meta import SolRpcErrorInfo
from ..utils.cached import cached_property


class SolRpcError(SolError):
    def __init__(self, src: SolRpcErrorInfo) -> None:
        super().__init__(src)
        self._rpc_data = src

    @cached_property
    def message(self) -> str:
        return getattr(self._rpc_data, "message", "<Unknown>")

    @property
    def rpc_data(self) -> SolRpcErrorInfo:
        return self._rpc_data


class SolBlockhashNotFound(SolError):
    @property
    def message(self) -> str:
        return"Blockhash not found"


class SolTxExecuteError(SolError):
    def __init__(self, data: CancelErrorData) -> None:
        super().__init__(data)
        self._data = data

    @property
    def message(self) -> str:
        return self._data.message

    @property
    def data(self) -> CancelErrorData:
        return self._data


class SolCbExceededBaseError(SolTxExecuteError):
    def __init__(self, cu_consumed: int) -> None:
        msg = f"Compute Budget exceeded: {cu_consumed}"
        super().__init__(
            CancelErrorData(
                CancelErrorSource.Proxy,
                ProxyCancelErrorCode.CbExceedError,
                msg,
            )
        )
        self._cu_consumed = cu_consumed

    @property
    def cu_consumed(self) -> int:
        return self._cu_consumed


class SolCbExceededError(SolCbExceededBaseError):
    pass


class SolCbExceededCriticalError(SolCbExceededBaseError):
    pass


class SolWritableError(SolTxExecuteError):
    def __init__(self) -> None:
        super().__init__(
            CancelErrorData(
                CancelErrorSource.Proxy,
                ProxyCancelErrorCode.WriteableError,
                "Privileges escalation error"
            )
        )


class SolNoMoreRetriesError(SolTxExecuteError):
    def __init__(self) -> None:
        super().__init__(
            CancelErrorData(
                CancelErrorSource.Proxy,
                ProxyCancelErrorCode.NoMoreRetriesError,
                "No more retries to commit transactions",
            )
        )


class SolUnknownReceiptError(SolTxExecuteError):
    pass


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
                CancelErrorSource.Neon,
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

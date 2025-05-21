from __future__ import annotations

from ..neon.cancel_error import CancelErrorData, CancelErrorSource, NeonProxyCancelErrorCode
from ..solana.errors import SolError
from ..solana.pubkey import SolPubKey
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


class SolTxExecError(SolError):
    def __init__(self, data: CancelErrorData) -> None:
        super().__init__(data)
        self._data = data

    @property
    def message(self) -> str:
        return self._data.message

    @property
    def data(self) -> CancelErrorData:
        return self._data


class SolCbExceededBaseError(SolTxExecError):
    def __init__(self, cu_consumed: int) -> None:
        msg = f"Compute Budget exceeded: {cu_consumed}"
        super().__init__(
            CancelErrorData(
                CancelErrorSource.NeonProxy,
                SolPubKey.default(),
                NeonProxyCancelErrorCode.CbExceedError,
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


class SolWritableError(SolTxExecError):
    def __init__(self) -> None:
        super().__init__(
            CancelErrorData(
                CancelErrorSource.NeonProxy,
                SolPubKey.default(),
                NeonProxyCancelErrorCode.WriteableError,
                "Privileges escalation error"
            )
        )


class SolUnsupportedProgError(SolTxExecError):
    def __init__(self) -> None:
        super().__init__(
            CancelErrorData(
                CancelErrorSource.NeonProxy,
                SolPubKey.default(),
                NeonProxyCancelErrorCode.UnsupportedProgError,
                "Unsupported program error"
            )
        )


class SolNoMoreRetriesError(SolTxExecError):
    def __init__(self) -> None:
        super().__init__(
            CancelErrorData(
                CancelErrorSource.NeonProxy,
                SolPubKey.default(),
                NeonProxyCancelErrorCode.NoMoreRetriesError,
                "No more retries to commit transactions",
            )
        )


class SolUnknownReceiptError(SolTxExecError):
    pass


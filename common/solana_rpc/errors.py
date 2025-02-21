from __future__ import annotations

import dataclasses
import enum
from typing import ClassVar

from ..neon.evm_log_decoder import NeonTxErrorLogInfo
from ..neon.transaction_model import NeonSkdTxStatus
from ..solana.errors import SolError
from ..solana.transaction_meta import SolRpcErrorInfo
from ..utils.cached import cached_property, cached_method


class SolErrorType(enum.IntEnum):
    Proxy = 1
    Neon = 2
    Solana = 3


class SolProxyErrorCode(enum.IntEnum):
    Unknown = 1
    Manual = 2
    NoMoreRetriesError = 3
    WriteableError = 4
    CbExceedError = 5


class SolErrorCode(enum.IntEnum):
    Unknown = 1
    Custom = 2


@dataclasses.dataclass(frozen=True)
class SolErrorData:
    error_type: SolErrorType
    code: int
    message: str

    _default: ClassVar[SolErrorData | None] = None

    @classmethod
    def default(cls) -> SolErrorData:
        if not cls._default:
            cls._default = cls(SolErrorType.Proxy, SolProxyErrorCode.Unknown, "Unknown")
        return cls._default

    @cached_method
    def to_bytes(self) -> bytes:
        err_data = self.message.encode("utf-8")
        return b"".join([
            int(self.error_type).to_bytes(1, "little"),
            self.code.to_bytes(2, "little"),
            len(err_data).to_bytes(2, "little"),
            err_data,
        ])


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
    def __init__(self, data: SolErrorData) -> None:
        super().__init__(data)
        self._data = data

    @property
    def message(self) -> str:
        return self._data.message

    @property
    def data(self) -> SolErrorData:
        return self._data


class SolCbExceededBaseError(SolTxExecuteError):
    def __init__(self, cu_consumed: int) -> None:
        msg = f"Compute Budget exceeded: {cu_consumed}"
        super().__init__(
            SolErrorData(
                SolErrorType.Proxy,
                SolProxyErrorCode.CbExceedError,
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
            SolErrorData(
                SolErrorType.Proxy,
                SolProxyErrorCode.WriteableError,
                "Privileges escalation error"
            )
        )


class SolNoMoreRetriesError(SolTxExecuteError):
    def __init__(self) -> None:
        super().__init__(
            SolErrorData(
                SolErrorType.Proxy,
                SolProxyErrorCode.NoMoreRetriesError,
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
            SolErrorData(
                SolErrorType.Neon,
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

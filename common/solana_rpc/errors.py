from ..solana.errors import SolError
from ..solana.transaction_meta import SolRpcErrorInfo


class SolRpcError(SolError):
    def __init__(self, src: SolRpcErrorInfo) -> None:
        super().__init__(getattr(src, "message", "<Unknown>"))
        self._rpc_data = src

    @property
    def rpc_data(self) -> SolRpcErrorInfo:
        return self._rpc_data


class SolWsCloseError(SolError):
    pass


class SolBlockhashNotFound(SolError):
    def __init__(self) -> None:
        super().__init__("Blockhash not found")


class SolNeonRequireResizeIterError(SolError):
    def __init__(self) -> None:
        super().__init__("NeonTx requires resize iterations")


class SolCbExceededError(SolError):
    def __init__(self) -> None:
        super().__init__("Compute Budget exceeded")


class SolCbExceededCriticalError(SolError):
    def __init__(self) -> None:
        super().__init__("Compute Budget is critically exceeded")


class SolOutOfMemoryError(SolError):
    def __init__(self) -> None:
        super().__init__("Out of memory")


class SolNoMoreRetriesError(SolError):
    def __init__(self) -> None:
        super().__init__("No more retries to commit transactions")


class SolUnknownReceiptError(SolError):
    def __init__(self):
        super().__init__("Unknown receipt")

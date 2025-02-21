from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_property


class SolError(Exception):
    def __init__(self, *args) -> None:
        BaseException.__init__(self, *args)

    @property
    def message(self) -> str:
        return "UNKNOWN"

    def to_string(self) -> str:
        return self.message

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class SolTxSizeError(SolError):
    def __init__(self, current_len: int, max_len: int) -> None:
        super().__init__(current_len, max_len)
        self._cur_len = current_len
        self._max_len = max_len

    @cached_property
    def message(self) -> str:
        return f"Transaction size is exceeded {self._cur_len} > {self._max_len}"


class SolAltError(SolError):
    def __init__(self, message: str, *args) -> None:
        super().__init__(message)
        self._msg = message

    @property
    def message(self) -> str:
        return self._msg


class SolAltContentError(SolAltError):
    def __init__(self, address: SolPubKey, message: str) -> None:
        super().__init__(message, address)
        self._addr = address

    @cached_property
    def message(self) -> str:
        return f"ALT {self._addr}: {self._msg}"


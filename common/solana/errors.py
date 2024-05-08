from common.solana.pubkey import SolPubKey


class SolError(Exception):
    def __init__(self, message: str) -> None:
        BaseException.__init__(self, message)
        self._msg = message

    @property
    def message(self) -> str:
        return self._msg

    def to_string(self) -> str:
        return self._msg

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class SolTxSizeError(SolError):
    def __init__(self, current_len: int, max_len: int) -> None:
        msg = f"Transaction size is exceeded {current_len} > {max_len}"
        super().__init__(msg)
        self._current_len = current_len
        self._max_len = max_len


class SolAltError(SolError):
    pass


class SolAltContentError(SolAltError):
    def __init__(self, address: SolPubKey, message: str) -> None:
        msg = f"ALT {address}: {message}"
        super().__init__(msg)

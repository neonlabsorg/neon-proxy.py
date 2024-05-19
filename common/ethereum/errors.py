from __future__ import annotations

from typing import Final, ClassVar

from .hash import EthAddress
from ..jsonrpc.errors import BaseJsonRpcError


class EthError(BaseJsonRpcError):
    pass


class EthWrongChainIdError(EthError):
    def __init__(self) -> None:
        super().__init__("wrong chain id")


class EthInvalidFilterError(EthError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code=-32600)


class EthNonceTooLowError(EthError):
    CODE: ClassVar[int] = -32002
    _empty_sender: Final[str] = "?"

    def __init__(self, tx_nonce: int, state_tx_cnt: int, *, sender: str | EthAddress = _empty_sender) -> None:
        msg = f"nonce too low: address {sender}, tx: {tx_nonce} state: {state_tx_cnt}"
        super().__init__(msg, code=self.CODE)

        self._sender = sender
        self._tx_nonce = tx_nonce
        self._state_tx_cnt = state_tx_cnt

    @property
    def state_tx_cnt(self) -> int:
        return self._state_tx_cnt

    @classmethod
    def raise_if_error(cls, tx_nonce: int, state_tx_cnt: int, *, sender: str = _empty_sender) -> None:
        if state_tx_cnt > tx_nonce:
            cls.raise_error(tx_nonce, state_tx_cnt, sender=sender)

    @classmethod
    def raise_error(cls, tx_nonce: int, state_tx_cnt: int, *, sender: str | EthAddress = _empty_sender) -> None:
        raise cls(tx_nonce, state_tx_cnt, sender=sender)


class EthNonceTooHighError(EthError):
    _empty_sender: Final[str] = "?"

    def __init__(self, tx_nonce: int, state_tx_cnt: int, *, sender: str | EthAddress = _empty_sender) -> None:
        msg = f"nonce too high: address {sender}, tx: {tx_nonce} state: {state_tx_cnt}"
        super().__init__(msg)
        self._sender = sender
        self._state_tx_cnt = state_tx_cnt
        self._tx_nonce = tx_nonce

    @property
    def state_tx_cnt(self) -> int:
        return self._state_tx_cnt

    @classmethod
    def raise_if_error(cls, tx_nonce: int, state_tx_cnt: int, *, sender: str | EthAddress = _empty_sender) -> None:
        if state_tx_cnt < tx_nonce:
            cls.raise_error(tx_nonce, state_tx_cnt, sender=sender)

    @classmethod
    def raise_error(cls, tx_nonce: int, state_tx_cnt: int, *, sender: str | EthAddress = _empty_sender) -> None:
        raise cls(tx_nonce, state_tx_cnt, sender=sender)


class EthOutOfGasError(EthError):
    _empty_sender: Final[str] = "?"

    def __init__(self, gas_limit: int, required_gas_limit: int, *, sender: str | EthAddress = _empty_sender) -> None:
        super().__init__("gas limit reached")
        self._sender = sender
        self._gas_limit = gas_limit
        self._required_gas_limit = required_gas_limit

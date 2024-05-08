from __future__ import annotations

from typing import Final, Annotated, Union

from typing_extensions import Self

from ..utils.cached import cached_method
from ..utils.format import hex_to_bytes, bytes_to_hex
from ..utils.pydantic import PlainValidator, PlainSerializer


class EthBinStr:
    _empty_data: Final[bytes] = bytes()
    null_str: Final[str] = "0x"

    def __init__(self, data: bytes):
        # pydantic.BaseModel validates field types in the constructor
        #  but this is a simple class, that is why the validation is implemented here
        if not isinstance(data, bytes):
            raise ValueError(f"Wrong input type {type(data).__name__}")

        self._data: Final[bytes] = data

    @classmethod
    def default(cls) -> Self:
        return cls(cls._empty_data)

    @classmethod
    def from_raw(cls, raw: _RawBinStr) -> Self:
        if not raw:
            return cls.default()
        elif isinstance(raw, cls):
            return raw

        data: bytes
        if isinstance(raw, str):
            data = hex_to_bytes(raw)
        elif isinstance(raw, bytearray):
            data = bytes(raw)
        else:
            data = raw

        return cls(data)

    @property
    def is_empty(self) -> bool:
        return not self._data

    @cached_method
    def _to_string(self) -> str:
        return bytes_to_hex(self._data)

    def to_string(self, default: str | None = null_str) -> str | None:
        return self._to_string() if self._data else default

    def to_bytes(self) -> bytes:
        return self._data

    def __str__(self) -> str:
        return self._to_string()

    def __repr__(self) -> str:
        return self._to_string()

    def __len__(self) -> int:
        return len(self._data)

    @cached_method
    def __hash__(self) -> int:
        return hash(self._data)

    def __eq__(self, other: _RawBinStr) -> bool:
        if other is self:
            return True
        elif isinstance(other, self.__class__):
            return self._data == other._data
        elif isinstance(other, str):
            return self.to_string() == other.lower()
        elif isinstance(other, bytes):
            return self._data == other
        elif isinstance(other, bytearray):
            return self._data == bytes(other)
        return False


_RawBinStr = Union[str, bytes, bytearray, EthBinStr, None]


EthBinStrField = Annotated[
    EthBinStr,
    PlainValidator(EthBinStr.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]

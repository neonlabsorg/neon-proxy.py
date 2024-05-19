from __future__ import annotations

from typing import ClassVar, Final, Annotated, Union

import eth_utils
from typing_extensions import Self

from ..utils.cached import cached_method
from ..utils.format import hex_to_bytes, bytes_to_hex
from ..utils.pydantic import PlainValidator, PlainSerializer


class _BaseHash:
    HashSize: ClassVar[int] = 0
    _empty_hash: Final[bytes] = bytes()
    _default: ClassVar[_BaseHash | None] = None

    def __init__(self, data: bytes):
        # pydantic.BaseModel validates field types in the constructor
        #  but this is a simple class, that is why the validation is implemented here

        if not isinstance(data, bytes):
            raise ValueError(f"Wrong input type {type(data).__name__}")
        elif len(data) not in (0, self.HashSize):
            raise ValueError(f"Wrong input len: {len(data)} not in (0, {self.HashSize})")

        self._data: Final[bytes] = data

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(cls._empty_hash)
        return cls._default

    @classmethod
    def from_raw(cls, raw: _RawHash) -> Self:
        if isinstance(raw, cls):
            return raw
        elif raw is None:
            return cls.default()

        data: bytes
        if isinstance(raw, str):
            data = hex_to_bytes(raw)
        elif isinstance(raw, bytearray):
            data = bytes(raw)
        else:
            data = raw

        return cls(data)

    @classmethod
    def from_not_none(cls, raw: _RawHash) -> Self:
        if raw is None:
            raise ValueError(f"Wrong input: null")
        return cls.from_raw(raw)

    @property
    def is_empty(self) -> bool:
        return not self._data

    def to_string(self, default: str | None = None) -> str | None:
        return self._to_string() if self._data else default

    @cached_method
    def _to_string(self) -> str:
        return bytes_to_hex(self._data)

    def to_bytes(self) -> bytes:
        return self._data

    @cached_method
    def __hash__(self) -> int:
        return hash(self._data)

    def __eq__(self, other: _RawHash) -> bool:
        if other is self:
            return True
        elif isinstance(other, self.__class__):
            return self._data == other._data
        elif isinstance(other, str):
            return self._to_string() == other.lower()
        elif isinstance(other, (bytes, bytearray)):
            return self._data == bytes(other)
        return False


_RawHash = Union[str, bytes, bytearray, _BaseHash, None]


class EthAddress(_BaseHash):
    HashSize: ClassVar[int] = 20
    ZeroAddress: ClassVar[str] = "0x" + "00" * HashSize

    def to_checksum(self, default: str | None = None) -> str | None:
        return self._to_checksum() if self._data else default

    @cached_method
    def _to_checksum(self) -> str | None:
        return eth_utils.to_checksum_address(self._data) if self._data else None

    def __str__(self) -> str:
        return self._to_checksum() or "None"

    def __repr__(self) -> str:
        return self._to_checksum() or "None"


EthAddressField = Annotated[
    EthAddress,
    PlainValidator(EthAddress.from_raw),
    PlainSerializer(lambda v: v.to_checksum(), return_type=str),
]
EthZeroAddressField = Annotated[
    EthAddress,
    PlainValidator(EthAddress.from_raw),
    PlainSerializer(lambda v: v.to_checksum(EthAddress.ZeroAddress), return_type=str),
]
EthNotNoneAddressField = Annotated[
    EthAddress,
    PlainValidator(EthAddress.from_not_none),
    PlainSerializer(lambda v: v.to_checksum(EthAddress.ZeroAddress), return_type=str),
]


class EthHash32(_BaseHash):
    HashSize: ClassVar[int] = 32
    ZeroHash: ClassVar[str] = "0x" + "00" * HashSize

    def to_string(self, default: str | None = None) -> str | None:
        return self._to_string() if self._data else default

    def __str__(self) -> str:
        return self._to_string() or "None"

    def __repr__(self) -> str:
        return self._to_string() or "None"


EthHash32Field = Annotated[
    EthHash32,
    PlainValidator(EthHash32.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]
EthZeroHash32Field = Annotated[
    EthHash32,
    PlainValidator(EthHash32.from_raw),
    PlainSerializer(lambda v: v.to_string(EthHash32.ZeroHash), return_type=str),
]
EthNotNoneHash32Field = Annotated[
    EthHash32,
    PlainValidator(EthHash32.from_not_none),
    PlainSerializer(lambda v: v.to_string(EthHash32.ZeroHash), return_type=str),
]

EthTxHash = EthHash32
EthTxHashField = EthNotNoneHash32Field
EthBlockHash = EthHash32
EthBlockHashField = EthNotNoneHash32Field

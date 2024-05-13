from __future__ import annotations

import base64
from typing import Annotated, Any

import base58
from pydantic import (
    BaseModel as _PydanticBaseModel,
    RootModel as _PydanticRootModel,
    ConfigDict,
    PlainValidator,
    PlainSerializer,
)
from typing_extensions import Self

from .cached import cached_method, cached_property, reset_cached_method
from .format import has_hex_start, hex_to_int, str_fmt_object


class BaseModel(_PydanticBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        ignored_types=(cached_property, cached_method, reset_cached_method),
    )

    @classmethod
    def from_json(cls, json_data: str) -> Self:
        return cls.model_validate_json(json_data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", by_alias=True)

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self


class RootModel(_PydanticRootModel):
    model_config = ConfigDict(
        strict=True,
        ignored_types=(cached_property, cached_method, reset_cached_method),
    )

    @classmethod
    def from_json(cls, json_data: str) -> Self:
        return cls.model_validate_json(json_data)

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls.model_validate(data)

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# Allows: 0x | 0X | 10 | 0xa | 0Xa | 0xA | 0XA | A
def _hex_to_int(value: str | int) -> int | None:
    if isinstance(value, str):
        if (len(value) == 2) and has_hex_start(value):
            return 0
        result = hex_to_int(value)
    elif isinstance(value, int):
        result = value
    else:
        raise ValueError(f"Wrong input type: {type(value).__name__}")

    if result < 0:
        raise ValueError("Input can't be a negative number")
    return result


def _uint_to_hex(value: int | None) -> str | None:
    if value is None:
        return None
    elif isinstance(value, int):
        if value < 0:
            raise ValueError("Input can't be a negative number")
        return hex(value)
    raise ValueError(f"Wrong input type: {type(value).__name__}")


def _uint_n_to_hex(value: int | None, size: int) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Input can't be a negative number")
        return "0x" + value.to_bytes(size, "big").hex()
    raise ValueError(f"Wrong input type: {type(value).__name__}")


def _uint8_to_hex(value: int | None) -> str | None:
    return _uint_n_to_hex(value, 8)


def _uint256_to_hex(value: int | None) -> str | None:
    return _uint_n_to_hex(value, 256)


HexUIntField = Annotated[int, PlainValidator(_hex_to_int), PlainSerializer(_uint_to_hex)]
HexUInt8Field = Annotated[int, PlainValidator(_hex_to_int), PlainSerializer(_uint8_to_hex)]
HexUInt256Field = Annotated[int, PlainValidator(_hex_to_int), PlainSerializer(_uint256_to_hex)]


# Allows: None | "1" | 1
def _dec_to_int(value: str | int | None) -> int | None:
    if not value:
        return 0
    elif isinstance(value, int):
        return value
    elif isinstance(value, str):
        return int(value)
    raise ValueError(f"Wrong input type: {type(value).__name__}")


DecIntField = Annotated[int, PlainValidator(_dec_to_int)]


# Allows: None | "hello" | b"hello"
def _str_to_bytes(value: str | bytes | bytearray | None) -> bytes | None:
    if not value:
        return bytes()
    elif isinstance(value, str):
        return bytes(value, "utf-8")
    elif isinstance(value, bytearray):
        return bytes(value)
    elif isinstance(value, bytes):
        return value
    raise ValueError(f"Wrong input type: {type(value).__name__}")


def _bytes_to_str(value: bytes) -> str | None:
    if isinstance(value, bytes):
        return str(value, "utf-8")
    raise ValueError(f"Wrong input type: {type(value).__name__}")


BytesField = Annotated[int, PlainValidator(_str_to_bytes), PlainSerializer(_bytes_to_str, return_type=str)]


# Allows: None | base64 | b"..." |
def _base64_to_bytes(value: str | bytes | bytearray | None) -> bytes:
    if not value:
        return bytes()
    elif isinstance(value, str):
        try:
            return base64.b64decode(value)
        except (BaseException,):
            raise ValueError("Wrong input type")
    elif isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError(f"Wrong input type: {type(value).__name__}")


def _bytes_to_base64(value: bytes | None) -> str:
    if not value:
        return ""
    return str(base64.b64encode(value), "utf-8")


Base64Field = Annotated[bytes, PlainValidator(_base64_to_bytes), PlainSerializer(_bytes_to_base64, return_type=str)]


# Allows: None | base58 | b"..." |
def _base58_to_bytes(value: str | bytes | bytearray | None) -> bytes:
    if not value:
        return bytes()
    elif isinstance(value, str):
        try:
            return base58.b58decode(value)
        except (BaseException,):
            raise ValueError("Wrong input type")
    elif isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError(f"Wrong input type: {type(value).__name__}")


def _bytes_to_base58(value: bytes | None) -> str:
    if not value:
        return ""
    return str(base58.b58encode(value), "utf-8")


Base58Field = Annotated[bytes, PlainValidator(_base58_to_bytes), PlainSerializer(_bytes_to_base58, return_type=str)]

from __future__ import annotations

from typing import Union, Annotated, ClassVar

import solders.hash as _hash
from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from ..utils.cached import cached_method

_SoldersSolHash = _hash.Hash


class SolBlockHash(_SoldersSolHash):
    _fake: ClassVar[SolBlockHash | None] = None
    _default: ClassVar[SolBlockHash | None] = None

    def __deepcopy__(self, memo: dict) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(_SoldersSolHash.default().__bytes__())
        return cls._default

    @classmethod
    def fake(cls) -> Self:
        if not cls._fake:
            cls._fake = cls.from_string("4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4")  # noqa
        return cls._fake

    @classmethod
    def new_unique(cls) -> Self:
        return cls(_SoldersSolHash.new_unique().__bytes__())

    @classmethod
    def from_raw(cls, raw: _RawHash) -> Self:
        if raw is None:
            return cls.default()
        elif isinstance(raw, cls):
            return raw
        elif isinstance(raw, _SoldersSolHash):
            return cls(raw.__bytes__())
        elif isinstance(raw, str):
            return cls.from_string(raw)
        elif isinstance(raw, (bytes, bytearray)):
            return cls.from_bytes(raw)
        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(_SoldersSolHash.from_string(raw).__bytes__())

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> Self:
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        return cls(raw)

    @classmethod
    def from_json(cls, raw: str) -> Self:
        return cls(_SoldersSolHash.from_json(raw).__bytes__())

    def to_string(self) -> str:
        return self.__str__()

    def to_bytes(self) -> bytes:
        return self.__bytes__()

    @property
    def is_empty(self) -> bool:
        return self.to_bytes() == self.default().to_bytes()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_method
    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        elif isinstance(other, _SoldersSolHash):
            return self.to_bytes() == other.__bytes__()
        elif isinstance(other, (bytearray, bytes)):
            return self.to_bytes() == bytes(other)
        elif isinstance(other, str):
            return self.to_string() == other
        return False


_RawHash = Union[None, str, bytes, _SoldersSolHash, SolBlockHash]


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
SolBlockHashField = Annotated[
    SolBlockHash,
    PlainValidator(SolBlockHash.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]

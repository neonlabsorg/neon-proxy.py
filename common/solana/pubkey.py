from __future__ import annotations

from typing import Sequence, Annotated, Union, ClassVar, Final

import solders.pubkey as _pk
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator
from typing_extensions import Self

from ..utils.cached import cached_method

_SoldersPubKey = _pk.Pubkey


class SolPubKey(_SoldersPubKey):
    _default: ClassVar[SolPubKey | None] = None
    key_size: Final[int] = _SoldersPubKey.LENGTH

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(_SoldersPubKey.default().__bytes__())
        return cls._default

    @classmethod
    def new_unique(cls) -> Self:
        return cls(_SoldersPubKey.new_unique().__bytes__())

    @classmethod
    def from_raw(cls, raw: _RawSolPubKey) -> Self:
        if isinstance(raw, cls):
            return raw
        elif raw is None:
            return cls.default()
        elif isinstance(raw, _SoldersPubKey):
            return cls(raw.__bytes__())
        elif isinstance(raw, str):
            return cls.from_string(raw)
        elif isinstance(raw, (bytes, bytearray)):
            return cls.from_bytes(raw)
        elif isinstance(raw, Sequence):
            return cls.from_sequence(raw)
        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @classmethod
    def from_string(cls, s: str) -> Self:
        return cls(_SoldersPubKey.from_string(s).__bytes__())

    @classmethod
    def from_sequence(cls, raw: Sequence[int]) -> Self:
        if len(raw) != 32:
            raise ValueError(f"Wrong length of raw: {len(raw)}")
        return cls(raw)

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> Self:
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        return cls(raw)

    @classmethod
    def from_json(cls, raw: str) -> Self:
        return cls(_SoldersPubKey.from_json(raw).__bytes__())

    @classmethod
    def create_with_seed(cls, base: _SoldersPubKey, seed: str, prog_id: _SoldersPubKey) -> Self:
        return cls(_SoldersPubKey.create_with_seed(base, seed, prog_id).__bytes__())

    @classmethod
    def create_program_address(cls, seeds: Sequence[bytes], prog_id: _SoldersPubKey) -> Self:
        return cls(_SoldersPubKey.create_program_address(seeds, prog_id).__bytes__())

    @classmethod
    def find_program_address(cls, seed_list: Sequence[bytes], prog_id: _SoldersPubKey) -> tuple[Self, int]:
        base_key, nonce = _SoldersPubKey.find_program_address(seed_list, prog_id)
        return cls(base_key.__bytes__()), nonce

    @property
    def is_empty(self) -> bool:
        return self.to_bytes() == self.default().to_bytes()

    def to_string(self) -> str:
        return self.__str__()

    def to_bytes(self) -> bytes:
        return self.__bytes__()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_method
    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __deepcopy__(self, memo: dict) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        elif isinstance(other, (bytearray, bytes)):
            return self.to_bytes() == bytes(other)
        elif isinstance(other, _SoldersPubKey):
            return self.to_bytes() == other.__bytes__()
        elif isinstance(other, str):
            return self.to_string() == other
        return False


_RawSolPubKey = Union[None, str, bytes, bytearray, Sequence[int], SolPubKey, _SoldersPubKey]


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
SolPubKeyField = Annotated[
    SolPubKey,
    PlainValidator(SolPubKey.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]

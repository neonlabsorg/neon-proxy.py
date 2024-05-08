from __future__ import annotations

import base64
from typing import Sequence, Union, Annotated

import solders.keypair as _key
from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from .pubkey import SolPubKey
from ..utils.cached import cached_property

SolKeyPair = _key.Keypair


class SolSigner:
    _default: SolSigner | None = None
    _fake: SolSigner | None = None

    def __init__(self, keypair: SolKeyPair) -> None:
        self._keypair = keypair

    @classmethod
    def default(cls) -> SolSigner:
        if cls._default is None:
            cls._default = SolSigner(SolKeyPair())
        return cls._default

    @classmethod
    def fake(cls) -> SolSigner:
        if not cls._fake:
            cls._fake = SolSigner.from_raw("ofdCncu8jex8e8jA/xehInTKRrawwsOouYShjss59Vo=")  # noqa
        return cls._fake

    @classmethod
    def from_raw(cls, raw: _RawAcct) -> Self:
        if isinstance(raw, SolSigner):
            return raw
        elif raw is None:
            return cls.default()
        elif isinstance(raw, SolKeyPair):
            return cls(raw)
        elif isinstance(raw, str):
            raw = base64.b64decode(raw)
            return cls(SolKeyPair.from_seed(raw))
        elif isinstance(raw, bytes):
            return cls(SolKeyPair.from_bytes(raw))
        elif isinstance(raw, Sequence):
            return cls(SolKeyPair.from_bytes(raw))
        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @property
    def secret(self) -> bytes:
        return self._keypair.secret()

    @cached_property
    def pubkey(self) -> SolPubKey:
        return SolPubKey.from_raw(self._keypair.pubkey())

    @property
    def keypair(self) -> SolKeyPair:
        return self._keypair

    def to_string(self) -> str:
        return self.pubkey.to_string()

    def to_base64_string(self) -> str:
        return str(base64.b64encode(self.secret), "utf-8")

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def to_bytes(self) -> bytes:
        return self._keypair.__bytes__()

    def __hash__(self) -> int:
        return self._keypair.__hash__()

    def __deepcopy__(self, memo: dict) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        elif isinstance(other, SolSigner):
            return self.pubkey == other.pubkey
        elif isinstance(other, SolKeyPair):
            return self.secret == other.secret()
        elif isinstance(other, str):
            return self.to_string() == other
        return False


_RawAcct = Union[SolSigner, SolKeyPair, bytes, Sequence[int], str, None]


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
SolSignerField = Annotated[
    SolSigner,
    PlainValidator(SolSigner.from_raw),
    PlainSerializer(lambda v: v.to_base64_string(), return_type=str),
]

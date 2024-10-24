from __future__ import annotations

from dataclasses import dataclass
from typing import Union, Annotated, ClassVar

import solders.rpc.responses as _resp
import solders.signature as _sig
from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from common.utils.cached import cached_method

SolRpcTxSigInfo = _resp.RpcConfirmedTransactionStatusWithSignature
_SoldersSig = _sig.Signature


class SolTxSig(_SoldersSig):
    _default: ClassVar[SolTxSig | None] = None

    def __deepcopy__(self, memo: dict) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(_SoldersSig.default().__bytes__())
        return cls._default

    @classmethod
    def new_unique(cls) -> Self:
        return cls(_SoldersSig.new_unique().__bytes__())

    @classmethod
    def from_raw(cls, raw: _RawSig) -> Self:
        if isinstance(raw, cls):
            return raw
        elif isinstance(raw, _SoldersSig):
            return cls(raw.__bytes__())
        elif isinstance(raw, str):
            return cls.from_string(raw)
        elif isinstance(raw, (bytearray, bytes)):
            return cls.from_bytes(raw)

        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(_SoldersSig.from_string(raw).__bytes__())

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> Self:
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        return cls(raw)

    @classmethod
    def from_json(cls, raw: str) -> Self:
        return cls(_SoldersSig.from_json(raw).__bytes__())

    def to_string(self) -> str:
        return self.__str__()

    def to_bytes(self) -> bytes:
        return self.__bytes__()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_method
    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        elif not isinstance(other, _SoldersSig):
            return False
        return other.__bytes__() == self.to_bytes()


_RawSig = Union[None, str, bytes, bytearray, _SoldersSig, SolTxSig]


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
SolTxSigField = Annotated[
    SolTxSig,
    PlainValidator(SolTxSig.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]


@dataclass(frozen=True)
class SolTxSigSlotInfo:
    slot: int
    sol_tx_sig: SolTxSig

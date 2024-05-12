from __future__ import annotations

from typing import Annotated

from pydantic import PlainValidator, PlainSerializer
from strenum import StrEnum
from typing_extensions import Self


class EthCommit(StrEnum):
    Pending = "pending"
    Latest = "latest"
    Safe = "safe"
    Finalized = "finalized"
    Earliest = "earliest"

    @classmethod
    def from_raw(cls, tag: str) -> Self:
        try:
            value = tag.lower()
            return cls(value)
        except (BaseException,):
            raise ValueError(f"Wrong commitment level {tag}")


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
EthCommitField = Annotated[
    EthCommit,
    PlainValidator(EthCommit.from_raw),
    PlainSerializer(lambda v: v.value, return_type=str),
]

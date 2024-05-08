from __future__ import annotations

from solders.commitment_config import CommitmentLevel as SolRpcCommit
from strenum import StrEnum
from typing_extensions import Self

from ..utils.cached import cached_method


class SolCommit(StrEnum):
    Processed = "processed"
    Confirmed = "confirmed"
    Safe = "safe"  # optimistic-finalized => 2/3 of validators
    Finalized = "finalized"
    Earliest = "earliest"

    @classmethod
    def from_raw(cls, tag: SolCommit | str | int) -> Self:
        value = tag
        if isinstance(value, cls):
            return value
        elif isinstance(value, int):
            if 0 <= value < len(cls):
                cls._build_member_names()
                value = cls._member_names_[value]  # noqa: see cls._build_member_names

        if isinstance(value, str):
            try:
                value = value.lower()
                return cls(value)
            except ValueError:
                pass

        raise ValueError(f"Wrong commitment level {tag}")

    @cached_method
    def to_level(self) -> int:
        for idx, item in enumerate(self.__class__.__members__.values()):
            if item.value == self.value:
                return idx
        return 100

    @cached_method
    def to_rpc_commit(self) -> SolRpcCommit:
        rpc_tag_dict: dict[SolCommit, SolRpcCommit] = {
            self.Processed: SolRpcCommit.Processed,
            self.Confirmed: SolRpcCommit.Confirmed,
            self.Safe: SolRpcCommit.Confirmed,
            self.Finalized: SolRpcCommit.Finalized,
            self.Earliest: SolRpcCommit.Finalized,
        }
        return rpc_tag_dict[self]

    @classmethod
    def _build_member_names(cls) -> None:
        if hasattr(cls, "_member_names_"):  # it's not documented property
            return
        cls._member_names_ = list(cls.__members__.keys())

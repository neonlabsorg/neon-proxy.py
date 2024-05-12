from __future__ import annotations

from typing import Union

from typing_extensions import Self

from ..ethereum.commit_level import EthCommit
from ..ethereum.hash import EthBlockHash, EthBlockHashField
from ..solana.block import SolRpcBlockInfo
from ..solana.commit_level import SolCommit
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel


class NeonBlockHdrModel(BaseModel):
    slot: int
    commit: EthCommit
    block_hash: EthBlockHashField
    block_time: int | None
    parent_slot: int | None
    parent_block_hash: EthBlockHashField

    @classmethod
    def default(cls) -> Self:
        return cls(
            slot=0,
            commit=EthCommit.Pending,
            block_hash=EthBlockHash.default(),
            block_time=None,
            parent_slot=None,
            parent_block_hash=EthBlockHashField.default(),
        )

    @classmethod
    def new_empty(cls, slot: int, commit: EthCommit = EthCommit.Pending) -> Self:
        return cls(
            slot=slot,
            commit=commit,
            block_hash=EthBlockHash.default(),
            block_time=None,
            parent_slot=None,
            parent_block_hash=EthBlockHashField.default(),
        )

    @classmethod
    def from_raw(cls, raw: _RawBlock) -> Self:
        if raw is None:
            return cls.default()
        elif isinstance(raw, cls):
            return cls
        elif isinstance(raw, int):
            return cls.new_empty(raw, EthCommit.Pending)
        elif isinstance(raw, dict):
            return cls.from_dict(raw)
        elif isinstance(raw, SolRpcBlockInfo):
            return cls._from_sol_block(raw)
        raise ValueError(f"Wrong input type: {type(raw).__name__}")

    @classmethod
    def _from_sol_block(cls, raw: SolRpcBlockInfo) -> Self:
        return cls(
            slot=raw.slot,
            commit=_SolEthCommit.to_eth_commit(raw.commit),
            block_hash=EthBlockHash.from_raw(raw.block_hash.to_bytes()),
            block_time=raw.block_time,
            parent_slot=raw.parent_slot,
            parent_block_hash=EthBlockHash.from_raw(raw.parent_block_hash.to_bytes()),
        )

    def to_pending(self) -> Self:
        return NeonBlockHdrModel(
            slot=self.slot + 1,
            commit=EthCommit.Pending,
            block_hash=EthBlockHash.default(),
            block_time=self.block_time,
            parent_slot=self.slot,
            parent_block_hash=self.block_hash,
        )

    def to_genesis_child(self, genesis_hash: EthBlockHash) -> Self:
        return NeonBlockHdrModel(
            slot=self.slot,
            commit=self.commit,
            block_hash=self.block_hash,
            block_time=self.block_time,
            parent_slot=self.slot,
            parent_block_hash=genesis_hash,
        )

    @property
    def is_empty(self) -> bool:
        return self.block_time is None

    @cached_property
    def is_finalized(self) -> bool:
        return self.commit == EthCommit.Finalized

    @property
    def has_error(self) -> bool:
        return self.error is not None


_RawBlock = Union[None, int, dict, NeonBlockHdrModel, SolRpcBlockInfo]


class _SolEthCommit:
    _eth_tag_dict = {
        SolCommit.Processed: EthCommit.Pending,
        SolCommit.Confirmed: EthCommit.Latest,
        SolCommit.Safe: EthCommit.Safe,
        SolCommit.Finalized: EthCommit.Finalized,
        SolCommit.Earliest: EthCommit.Earliest,
    }

    @classmethod
    def to_eth_commit(cls, commit: SolCommit) -> EthCommit:
        return cls._eth_tag_dict.get(commit, EthCommit.Pending)

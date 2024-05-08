from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Union

import solders.transaction_status as _tx
from typing_extensions import Self

from .commit_level import SolCommit
from .hash import SolBlockHash
from .transaction_meta import SolRpcTxInfo

_SoldersRpcBlockInfo = _tx.UiConfirmedBlock


@dataclass(frozen=True)
class SolRpcBlockInfo:
    slot: int
    commit: SolCommit
    block_hash: SolBlockHash
    block_time: int | None
    block_height: int | None
    parent_slot: int | None
    parent_block_hash: SolBlockHash
    tx_list: list[SolRpcTxInfo]

    @classmethod
    def default(cls) -> Self:
        return cls.new_empty(0)

    @classmethod
    def new_empty(cls, slot: int, *, commit=SolCommit.Processed) -> Self:
        return cls(
            slot=slot,
            commit=commit,
            block_hash=SolBlockHash.default(),
            block_time=None,
            block_height=None,
            parent_slot=None,
            parent_block_hash=SolBlockHash.default(),
            tx_list=list(),
        )

    @classmethod
    def from_raw(cls, raw: _RawBlock, *, slot: int | None = None, commit=SolCommit.Processed) -> Self:
        if raw is None:
            return cls.new_empty(slot, commit=commit)
        elif isinstance(raw, cls):
            assert slot is None, "The block slot can't be change"

            # But commit can be change
            if commit != SolCommit.Processed:
                return dataclasses.replace(raw, commit=commit)

            return raw
        elif isinstance(raw, int):
            assert slot is None, "The block slot is already passed in the raw parameter"
            return cls.new_empty(raw, commit=commit)
        elif isinstance(raw, _SoldersRpcBlockInfo):
            return cls._from_rpc_block(slot, raw, commit)
        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @classmethod
    def _from_rpc_block(cls, slot: int, rpc_block: _SoldersRpcBlockInfo, commit: SolCommit) -> Self:
        assert slot is not None, "The block slot should be defined"
        assert commit != SolCommit.Processed, "The commitment should be defined"
        return cls(
            slot=slot,
            commit=commit,
            block_hash=SolBlockHash.from_raw(rpc_block.blockhash),
            block_time=rpc_block.block_time,
            block_height=rpc_block.block_height,
            parent_slot=rpc_block.parent_slot,
            parent_block_hash=SolBlockHash.from_raw(rpc_block.previous_blockhash),
            tx_list=rpc_block.transactions,
        )

    @property
    def is_finalized(self) -> bool:
        return self.commit in (SolCommit.Finalized, SolCommit.Earliest)

    @property
    def is_empty(self) -> bool:
        return not self.block_time

    def mark_finalized(self) -> None:
        object.__setattr__(self, "commit", SolCommit.Finalized)


_RawBlock = Union[None, dict, _SoldersRpcBlockInfo, SolRpcBlockInfo]

from __future__ import annotations

import math
from typing import Union

from typing_extensions import Self

from common.solana.transaction_decoder import SolTxMetaInfo

from ..ethereum.commit_level import EthCommit, EthCommitField
from ..ethereum.hash import EthBlockHash, EthBlockHashField
from ..solana.block import SolRpcBlockInfo
from ..solana.commit_level import SolCommit
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel


class NeonBlockHdrModel(BaseModel):
    slot: int
    commit: EthCommitField
    block_hash: EthBlockHashField
    block_time: int | None
    parent_slot: int | None
    parent_block_hash: EthBlockHashField
    priority_fee_percentiles: list[int]

    @classmethod
    def default(cls) -> Self:
        return cls(
            slot=0,
            commit=EthCommit.Pending,
            block_hash=EthBlockHash.default(),
            block_time=None,
            parent_slot=None,
            parent_block_hash=EthBlockHashField.default(),
            priority_fee_percentiles=[0] * 11,  # Although this path is not used, let's make it future-proof.
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
            priority_fee_percentiles=[0] * 11,  # Although this path is not used, let's make it future-proof.
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
            priority_fee_percentiles=cls._calculate_priority_fee_stats(raw),
        )

    @classmethod
    def _calculate_priority_fee_stats(cls, sol_block: SolRpcBlockInfo) -> list[int]:
        # In case for some reason, Solana block does not have any transactions.
        if not sol_block.tx_list:
            return [0] * 11

        # Build a full list of compute unit prices in the solana block.
        prices: list[int] = list()
        for sol_tx in sol_block.tx_list:
            sol_tx_meta = SolTxMetaInfo.from_raw(sol_block.slot, sol_tx)
            prices.append(sol_tx_meta.sol_tx_cu.cu_price)
        # Sort.
        prices.sort()
        # Take every i * 10 percentile (i:=0..10) in a sorted list.
        return [prices[math.ceil(p * (len(prices) - 1) / 100)] for p in range(0, 101, 10)]

    def to_pending(self) -> Self:
        return NeonBlockHdrModel(
            slot=self.slot + 1,
            commit=EthCommit.Pending,
            block_hash=EthBlockHash.default(),
            block_time=self.block_time,
            parent_slot=self.slot,
            parent_block_hash=self.block_hash,
            priority_fee_percentiles=self.priority_fee_percentiles,
        )

    def to_genesis_child(self, genesis_hash: EthBlockHash) -> Self:
        return NeonBlockHdrModel(
            slot=self.slot,
            commit=self.commit,
            block_hash=self.block_hash,
            block_time=self.block_time,
            parent_slot=self.slot,
            parent_block_hash=genesis_hash,
            priority_fee_percentiles=self.priority_fee_percentiles,
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

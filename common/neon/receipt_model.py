from __future__ import annotations

import logging
from typing import Any, Union

from pydantic import Field
from typing_extensions import Self

from .evm_log_decoder import NeonTxEventModel, NeonTxLogReturnInfo
from ..ethereum.hash import EthBlockHash, EthBlockHashField, EthTxHashField
from ..solana.signature import SolTxSig, SolTxSigField
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel, HexUIntField

_LOG = logging.getLogger(__name__)


class NeonTxReceiptModel(BaseModel):
    slot: int | None
    block_hash: EthBlockHashField
    # Solana instruction with Neon Receipt
    sol_tx_sig: SolTxSigField
    sol_ix_idx: int | None
    sol_inner_ix_idx: int | None
    # Ethereum-like status
    neon_tx_idx: int | None
    status: HexUIntField
    # Gas usage
    total_gas_used: HexUIntField
    sum_gas_used: HexUIntField
    priority_fee_used: HexUIntField
    base_fee_used: HexUIntField
    # Neon+Ethereum-like events
    event_list: list[NeonTxEventModel] = Field(default_factory=list)
    # if NeonTx was canceled
    is_canceled: bool
    # parent and childs for scheduling
    parent_tx_list: list[EthTxHashField] = Field(default_factory=list)
    child_tx_list: list[EthTxHashField] = Field(default_factory=list)

    @classmethod
    def default(cls) -> Self:
        return cls(
            slot=0,
            block_hash=EthBlockHash.default(),
            sol_tx_sig=SolTxSig.default(),
            sol_ix_idx=None,
            sol_inner_ix_idx=None,
            neon_tx_idx=None,
            status=NeonTxLogReturnInfo.Failed,
            total_gas_used=0,
            sum_gas_used=0,
            priority_fee_used=0,
            base_fee_used=0,
            event_list=list(),
            is_canceled=False,
            parent_tx_list=list(),
            child_tx_list=list(),
        )

    @classmethod
    def from_raw(cls, raw: _RawTxReceipt) -> Self:
        if raw is None:
            return cls.default()
        elif raw is cls:
            return raw
        elif raw is dict:
            return cls.from_dict(raw)
        raise ValueError(f"Wrong input type {type(raw).__name__}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    @cached_property
    def log_bloom(self) -> int:
        value = 0
        for event in self.event_list:
            value |= event.log_bloom
        return value

    @cached_property
    def base_fee_per_gas(self) -> int:
        return self.base_fee_used // self.total_gas_used

    @cached_property
    def priority_fee_per_gas(self) -> int:
        return self.priority_fee_used // self.total_gas_used

    @cached_property
    def is_failed(self) -> bool:
        return self.status == NeonTxLogReturnInfo.Failed


_RawTxReceipt = Union[NeonTxReceiptModel, dict, None]

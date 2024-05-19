from __future__ import annotations

import logging
from typing import Any, Union

from typing_extensions import Self

from .evm_log_decoder import NeonTxEventModel
from ..ethereum.hash import EthBlockHash, EthBlockHashField
from ..solana.signature import SolTxSig, SolTxSigField
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel, HexUIntField

_LOG = logging.getLogger(__name__)


class NeonTxReceiptModel(BaseModel):
    slot: int | None
    block_hash: EthBlockHashField

    sol_tx_sig: SolTxSigField
    sol_ix_idx: int | None
    sol_inner_ix_idx: int | None

    neon_tx_idx: int | None
    status: HexUIntField

    total_gas_used: HexUIntField
    sum_gas_used: HexUIntField

    event_list: list[NeonTxEventModel]

    is_completed: bool
    is_canceled: bool

    @classmethod
    def default(cls) -> Self:
        return cls(
            slot=0,
            block_hash=EthBlockHash.default(),
            sol_tx_sig=SolTxSig.default(),
            sol_ix_idx=None,
            sol_inner_ix_idx=None,
            neon_tx_idx=None,
            status=0,
            total_gas_used=0,
            sum_gas_used=0,
            event_list=list(),
            is_completed=False,
            is_canceled=False,
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

    @property
    def is_valid(self) -> bool:
        return self.is_completed


_RawTxReceipt = Union[NeonTxReceiptModel, dict, None]

from __future__ import annotations

from dataclasses import dataclass

from typing_extensions import Self

from common.ethereum.hash import EthAddress
from common.utils.cached import cached_method
from ..base.mp_api import MpTxModel


@dataclass(frozen=True)
class SenderNonce:
    sender: EthAddress
    chain_id: int
    nonce: int

    @classmethod
    def from_raw(cls, tx: MpTxModel | tuple[EthAddress, int, int]) -> Self:
        if isinstance(tx, MpTxModel):
            return cls(tx.sender, tx.chain_id, tx.nonce)
        return cls(*tx)

    @cached_method
    def to_string(self) -> str:
        return f"{self.sender}:0x{self.chain_id:x}:0x{self.nonce:x}"

    def __hash__(self) -> int:
        return hash((self.sender, self.chain_id, self.nonce))

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        elif not isinstance(other, SenderNonce):
            return False
        return (self.sender, self.chain_id, self.nonce) == (other.sender, other.chain_id, other.nonce)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

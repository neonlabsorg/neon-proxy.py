from __future__ import annotations

from .receipt_model import NeonTxReceiptModel
from .transaction_model import NeonTxModel
from ..ethereum.hash import EthTxHash
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel


class NeonTxMetaModel(BaseModel):
    neon_tx: NeonTxModel
    neon_tx_rcpt: NeonTxReceiptModel

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self.neon_tx.neon_tx_hash

    @cached_property
    def effective_gas_price(self) -> int:
        return self.calc_effective_gas_price(self.neon_tx, self.neon_tx_rcpt)

    @classmethod
    def calc_effective_gas_price(cls, neon_tx: NeonTxModel, neon_tx_rcpt: NeonTxReceiptModel) -> int:
        if neon_tx_rcpt.priority_fee_used:
            effective_gas_price = neon_tx.base_fee_per_gas + neon_tx_rcpt.priority_fee_per_gas
        elif neon_tx_rcpt.base_fee_used:
            effective_gas_price = neon_tx.max_priority_fee_per_gas + neon_tx_rcpt.base_fee_per_gas
        else:
            effective_gas_price = neon_tx.effective_gas_price

        return effective_gas_price

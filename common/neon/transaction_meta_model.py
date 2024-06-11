from __future__ import annotations

from .receipt_model import NeonTxReceiptModel
from .transaction_model import NeonTxModel
from ..ethereum.hash import EthTxHash
from ..utils.pydantic import BaseModel


class NeonTxMetaModel(BaseModel):
    neon_tx: NeonTxModel
    neon_tx_rcpt: NeonTxReceiptModel

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self.neon_tx.neon_tx_hash

    @property
    def effective_gas_price(self) -> int:
        effective_gas_price = self.neon_tx.gas_price
        if self.neon_tx.is_dynamic_gas_tx:
            # Effective gas price is equal to base_fee_per_gas + math.ceil(priority_fee_spent / total_gas_used).
            effective_gas_price = self.neon_tx.max_fee_per_gas - self.neon_tx.max_priority_fee_per_gas
            # However, math.ceil does floating-point math and sometimes gives incorrect results due to precision.
            # So, it's better to use a little trick: ceildiv(a,b) := -(a // -b).
            effective_gas_price -= self.neon_tx_rcpt.priority_fee_spent // -self.neon_tx_rcpt.total_gas_used
        return effective_gas_price

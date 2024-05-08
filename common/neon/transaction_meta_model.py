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

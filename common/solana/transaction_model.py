from enum import IntEnum
from typing import Annotated

from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from .transaction import SolTx
from .transaction_legacy import SolLegacyTx
from .transaction_v0 import SolV0Tx
from ..utils.pydantic import BaseModel


class SolTxType(IntEnum):
    Legacy = 0
    Version0 = 1


SolTxTypeField = Annotated[
    SolTxType,
    PlainValidator(lambda v: SolTxType(v)),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class SolTxModel(BaseModel):
    tx_type: SolTxTypeField
    tx_data: dict

    @classmethod
    def from_raw(cls, tx: SolTx) -> Self:
        if not isinstance(tx, (SolLegacyTx, SolV0Tx)):
            raise ValueError(f"Wrong input type {type(tx).__name__}")

        tx_type = SolTxType.Legacy if isinstance(tx, SolLegacyTx) else SolTxType.Version0
        return cls(tx_type=tx_type, tx_data=tx.to_dict())

    @property
    def tx(self) -> SolTx:
        if self.tx_type == SolTxType.Legacy:
            return SolLegacyTx.from_dict(self.tx_data)
        elif self.tx_type == SolTxType.Version0:
            return SolV0Tx.from_dict(self.tx_data)

        raise ValueError(f"Wrong input type {self.tx_type}")

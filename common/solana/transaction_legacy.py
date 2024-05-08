from __future__ import annotations

import solders.message as _msg
import solders.transaction as _tx
from typing_extensions import Self

from .signature import SolTxSig
from .signer import SolSigner
from .transaction import SolTx
from ..utils.pydantic import BaseModel, Base64Field

SolLegacyMsg = _msg.Message
_SoldersLegacyTx = _tx.Transaction


class SolLegacyTx(SolTx):
    """Legacy transaction class to represent an atomic transaction."""

    class _Model(BaseModel):
        name: str
        data: Base64Field
        is_signed: bool
        is_cloned: bool

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        model = cls._Model.from_dict(data)

        self = cls(model.name, tuple())
        self._solders_legacy_tx = _SoldersLegacyTx.from_bytes(model.data)
        self._is_signed = model.is_signed
        self._is_cloned = model.is_cloned
        return self

    def to_dict(self) -> dict:
        return self._Model(
            name=self._name,
            data=bytes(self._solders_legacy_tx),
            is_signed=self._is_signed,
            is_cloned=self._is_cloned,
        ).to_dict()

    @property
    def message(self) -> SolLegacyMsg:
        return self._solders_legacy_tx.message

    def _serialize(self) -> bytes:
        return bytes(self._solders_legacy_tx)

    def _sig(self) -> SolTxSig:
        return SolTxSig.from_raw(self._solders_legacy_tx.signatures[0])

    def _sign(self, signer: SolSigner) -> None:
        self._solders_legacy_tx.sign((signer.keypair,), self._solders_legacy_tx.message.recent_blockhash)

    def _clone(self) -> SolLegacyTx:
        return SolLegacyTx(self.name, self._decode_ix_list())

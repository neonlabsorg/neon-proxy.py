from __future__ import annotations

from typing import Sequence

from typing_extensions import Self

from .pubkey import SolPubKey, SolPubKeyField
from .transaction_legacy import SolLegacyTx
from .errors import SolAltContentError
from .alt_list_filter import SolAltListFilter
from .alt_program import SolAltID, SolAltAccountInfo
from ..utils.pydantic import BaseModel


class SolAltInfo:
    class _Model(BaseModel):
        ident: SolAltID
        owner: SolPubKeyField
        account_key_list: list[SolPubKeyField]
        new_account_key_list: list[SolPubKeyField]
        is_exist: bool

    def __init__(self, ident: SolAltID):
        self._ident = ident
        self._owner = ident.owner
        self._acct_key_list: list[SolPubKey] = list()
        self._new_acct_key_set: set[SolPubKey] = set()
        self._is_exist = False

    @classmethod
    def from_legacy_tx(cls, ident: SolAltID, legacy_tx: SolLegacyTx) -> Self:
        self = cls(ident)

        legacy_msg = legacy_tx.message
        alt_filter = SolAltListFilter(legacy_msg)

        self._acct_key_list = list(alt_filter.alt_account_key_set)
        self._new_acct_key_set = set(self._acct_key_list)
        self._is_exist = False

        if not self._acct_key_list:
            raise SolAltContentError(self.address, "no accounts for the lookup table")
        return self

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        model = cls._Model.from_dict(data)

        self = cls(model.ident)
        self._owner = model.owner
        self._acct_key_list = model.account_key_list
        self._new_acct_key_set = set(model.new_account_key_list)
        self._is_exist = model.is_exist
        return self

    def to_dict(self) -> dict:
        return self._Model(
            ident=self._ident,
            owner=self._owner,
            account_key_list=self._acct_key_list,
            new_account_key_list=list(self._new_acct_key_set),
            is_exist=self._is_exist,
        ).dict()

    @property
    def ident(self) -> SolAltID:
        return self._ident

    @property
    def address(self) -> SolPubKey:
        return self._ident.address

    @property
    def owner(self) -> SolPubKey:
        return self._owner

    @property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple(self._acct_key_list)

    @property
    def new_account_key_set(self) -> set[SolPubKey]:
        return self._new_acct_key_set

    @property
    def is_exist(self) -> bool:
        return self._is_exist

    def remove_account_key_list(self, account_key_list: Sequence[SolPubKey]) -> bool:
        if self._is_exist:
            raise SolAltContentError(self.address, "trying to remove account from existing address lookup table")

        old_len = len(self._acct_key_list)
        for acct_key in account_key_list:
            if (idx := next((idx for idx, value in enumerate(self._acct_key_list) if value == acct_key), -1)) == -1:
                continue
            self._acct_key_list.pop(idx)
            self._new_acct_key_set.discard(acct_key)
        return old_len != len(self._acct_key_list)

    def add_account_key_list(self, account_key_list: Sequence[SolPubKey]) -> None:
        if not self._is_exist:
            raise SolAltContentError(self.address, "trying to add account to not-existing lookup table")

        for acct_key in account_key_list:
            if (idx := next((idx for idx, value in enumerate(self._acct_key_list) if value == acct_key), -1)) != -1:
                continue
            self._acct_key_list.append(acct_key)
            self._new_acct_key_set.add(acct_key)

    def update_from_account(self, alt_account_info: SolAltAccountInfo) -> None:
        if self._ident.address != alt_account_info.address:
            raise SolAltContentError(
                self.address,
                f"trying to update account list from another lookup table {alt_account_info.address}",
            )

        self._acct_key_list = list(alt_account_info.account_key_list)
        self._new_acct_key_set: set[SolPubKey] = set()
        self._owner = alt_account_info.owner
        self._is_exist = True

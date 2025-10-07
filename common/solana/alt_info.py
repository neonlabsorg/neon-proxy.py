from __future__ import annotations

from typing import Sequence, Self

from .alt_list_filter import SolAltListFilter
from .alt_program import SolAltID, SolAltAccountInfo
from .errors import SolAltContentError
from .pubkey import SolPubKey, SolPubKeyField
from .transaction_legacy import SolLegacyTx
from ..utils.pydantic import BaseModel


class SolAltInfo:
    class _Model(BaseModel):
        ident: SolAltID
        owner: SolPubKeyField
        account_key_list: list[SolPubKeyField]
        new_account_key_list: list[SolPubKeyField]
        is_exist: bool

    def __init__(self, ident: SolAltID, *, is_fake: bool = False) -> None:
        self._ident = ident
        self._owner = ident.owner
        self._is_fake = is_fake
        self._acct_key_list: list[SolPubKey] = list()
        self._new_acct_key_set: set[SolPubKey] = set()
        self._is_exist = False

    @classmethod
    def from_legacy_tx(cls, ident: SolAltID, legacy_tx: SolLegacyTx, *, is_fake: bool = False) -> Self:
        self = cls(ident, is_fake=is_fake)

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

    def clone(self, *, account_limit: int = 0, ident: SolAltID | None = None, is_fake: bool = False) -> Self:
        if not ident:
            ident = self._ident
            is_fake = self._is_fake
        new_self = self.__class__(ident, is_fake=is_fake)

        if account_limit and (len(self._acct_key_list) > account_limit):
            new_self._acct_key_list = self._acct_key_list[:account_limit]
            new_self._new_acct_key_set = self._new_acct_key_set.intersection(new_self._acct_key_list)
        else:
            new_self._acct_key_list = self._acct_key_list
            new_self._new_acct_key_set = self._new_acct_key_set

        return new_self

    def to_dict(self) -> dict:
        return self._Model(
            ident=self._ident,
            owner=self._owner,
            account_key_list=self._acct_key_list,
            new_account_key_list=list(self._new_acct_key_set),
            is_exist=self._is_exist,
        ).to_dict()

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
    def account_key_list(self) -> Sequence[SolPubKey]:
        return tuple(self._acct_key_list)

    @property
    def new_account_key_set(self) -> set[SolPubKey]:
        return self._new_acct_key_set

    @property
    def is_exist(self) -> bool:
        return self._is_exist

    @property
    def is_fake(self) -> bool:
        return self._is_fake

    def remove_account_key_list(self, account_key_list: Sequence[SolPubKey]) -> bool:
        if self._is_exist:
            raise SolAltContentError(self.address, "trying to remove account from existing address lookup table")

        old_len = len(self._acct_key_list)
        for acct_key in account_key_list:
            try:
                idx = self._acct_key_list.index(acct_key)
                self._acct_key_list.pop(idx)
                self._new_acct_key_set.discard(acct_key)
            except ValueError:
                pass

        return old_len != len(self._acct_key_list)

    def add_account_key_list(self, account_key_list: Sequence[SolPubKey]) -> None:
        if not self._is_exist:
            raise SolAltContentError(self.address, "trying to add account to not-existing lookup table")

        for acct_key in account_key_list:
            if acct_key in self._acct_key_list:
                continue
            self._acct_key_list.append(acct_key)
            self._new_acct_key_set.add(acct_key)

    def update_from_account(self, alt_account: SolAltAccountInfo) -> None:
        if alt_account.address not in (self._ident.address, SolPubKey.default()):
            raise SolAltContentError(
                self.address,
                f"trying to update account list from another lookup table {alt_account.address}",
            )

        self._acct_key_list = list(alt_account.account_key_list)
        self._new_acct_key_set: set[SolPubKey] = set()
        self._owner = alt_account.owner
        self._is_exist = alt_account.is_exist

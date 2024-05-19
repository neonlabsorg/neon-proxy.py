from __future__ import annotations

import logging
from enum import IntEnum
from typing import Final, Sequence

import solders.address_lookup_table_account as _alt
import solders.system_program as _sys
from typing_extensions import Self

from .instruction import SolTxIx
from .pubkey import SolPubKey, SolPubKeyField
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class SolAltIxCode(IntEnum):
    Create = 0
    Freeze = 1
    Extend = 2
    Deactivate = 3
    Close = 4


class SolAltID(BaseModel):
    address: SolPubKeyField
    owner: SolPubKeyField
    recent_slot: int
    nonce: int

    @cached_property
    def ctx_id(self) -> str:
        return self.owner.to_string()[:8] + ":" + self.address.to_string()[:8]

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other) -> bool:
        return isinstance(other, SolAltID) and self.address == other.address


class SolAltProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_alt.ID)
    MaxRequiredSigCnt: Final[int] = 19
    MaxTxAccountCnt: Final[int] = 27
    MaxAltAccountCnt: Final[int] = _alt.LOOKUP_TABLE_MAX_ADDRESSES

    def __init__(self, payer: SolPubKey) -> None:
        self._payer = payer

    def derive_alt_address(self, recent_slot: int) -> SolAltID:
        addr, nonce = SolPubKey.find_program_address(
            seed_list=(
                self._payer.to_bytes(),
                recent_slot.to_bytes(8, "little"),
            ),
            prog_id=self.ID,
        )
        return SolAltID(owner=self._payer, address=addr, recent_slot=recent_slot, nonce=nonce)

    def make_create_alt_ix(self, ident: SolAltID) -> SolTxIx:
        assert ident.owner == self._payer, "Wrong owner of the ALT"

        ix, addr = _sys.create_lookup_table(
            _sys.CreateLookupTableParams(
                authority_address=self._payer,
                payer_address=self._payer,
                recent_slot=ident.recent_slot,
            )
        )

        assert (
            addr == ident.address
        ), "The parameters for creating ALT don't satisfy conditions for generating the address of ALT"
        return ix

    def make_extend_alt_ix(self, ident: SolAltID, account_key_list: Sequence[SolPubKey]) -> SolTxIx:
        assert len(account_key_list), "No accounts for ALT extending"
        return _sys.extend_lookup_table(
            _sys.ExtendLookupTableParams(
                payer_address=self._payer,
                lookup_table_address=ident.address,
                authority_address=self._payer,
                new_addresses=list(account_key_list),
            )
        )

    def make_deactivate_alt_ix(self, ident: SolAltID) -> SolTxIx:
        return _sys.deactivate_lookup_table(
            _sys.DeactivateLookupTableParams(
                lookup_table_address=ident.address,
                authority_address=self._payer,
            )
        )

    def make_close_alt_ix(self, ident: SolAltID) -> SolTxIx:
        return _sys.close_lookup_table(
            _sys.CloseLookupTableParams(
                lookup_table_address=ident.address,
                authority_address=self._payer,
                recipient_address=self._payer,
            )
        )


class SolAltAccountInfo:
    _max_u64: Final[int] = 2 ** 64 - 1

    def __init__(self, address: SolPubKey, data: bytes | None) -> None:
        self._addr = address
        self._meta: _alt.LookupTableMeta | None = None
        self._addr_list_data = bytes()

        if not data:
            return
        elif len(data) < _alt.LOOKUP_TABLE_META_SIZE:
            _LOG.error("ALT %s doesn't have a meta, len %s", address, len(data))
            return

        addr_list_len = len(data) - _alt.LOOKUP_TABLE_META_SIZE
        if addr_list_len % SolPubKey.KeySize:
            _LOG.error("ALT %s addresses list has bad length %s", address, addr_list_len)
            return

        # skip 4 bytes of type of lookup table
        self._meta = _alt.LookupTableMeta.from_bytes(data[4:])
        self._addr_list_data = data[_alt.LOOKUP_TABLE_META_SIZE:]

    @classmethod
    def from_bytes(cls, address: SolPubKey, data: bytes | None) -> Self:
        return cls(address, data)

    @property
    def is_empty(self) -> bool:
        return not self._meta

    @property
    def address(self) -> SolPubKey:
        return self._addr

    @cached_property
    def owner(self) -> SolPubKey:
        return SolPubKey.from_raw(getattr(self._meta, "authority", None)) if self._meta else SolPubKey.default()

    @cached_property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        # tried solders, but _alt.AddressLookupTable doesn't work...
        offset = 0
        acct_key_cnt = len(self._addr_list_data) // SolPubKey.KeySize
        acct_key_list = list()
        for _ in range(acct_key_cnt):
            key = SolPubKey.from_bytes(self._addr_list_data[offset:offset + SolPubKey.KeySize])
            offset += SolPubKey.KeySize
            acct_key_list.append(key)

        self._addr_list_data = bytes()
        return tuple(acct_key_list)

    @property
    def last_extended_slot(self) -> int:
        return self._meta.last_extended_slot if self._meta else 0

    @property
    def deactivation_slot(self) -> int:
        return self._meta.deactivation_slot if self._meta else 0

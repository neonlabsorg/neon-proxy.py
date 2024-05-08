from __future__ import annotations

import math
from enum import IntEnum
from typing import Final, Sequence

import solders.address_lookup_table_account as _alt
import solders.system_program as _sys
from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64ul
from construct import Struct
from typing_extensions import Self

from .instruction import SolTxIx
from .pubkey import SolPubKey, SolPubKeyField
from ..utils.pydantic import BaseModel


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

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other) -> bool:
        return isinstance(other, SolAltID) and self.address == other.address


class SolAltProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_alt.ID)
    MaxRequiredSigCnt: Final[int] = 19
    MaxTxAccountCnt: Final[int] = 27
    MaxAltAccountCnt: Final[int] = _alt.LOOKUP_TABLE_MAX_ADDRESSES

    def __init__(self, owner: SolPubKey) -> None:
        self._owner = owner

    def derive_lookup_table_address(self, recent_slot: int) -> SolAltID:
        addr, nonce = SolPubKey.find_program_address(
            seeds=(
                self._owner.to_bytes(),
                recent_slot.to_bytes(8, "little"),
            ),
            prog_id=self.ID,
        )
        return SolAltID(owner=self._owner, address=addr, recent_slot=recent_slot, nonce=nonce)

    def make_create_lookup_table_ix(self, ident: SolAltID) -> SolTxIx:
        assert ident.owner == self._owner, "Wrong owner of the ALT"

        ix, addr = _sys.create_lookup_table(
            _sys.CreateLookupTableParams(
                authority_address=self._owner,
                payer_address=self._owner,
                recent_slot=ident.recent_slot,
            )
        )

        assert (
            addr == ident.address
        ), "The parameters for creating ALT don't satisfy conditions for generating the address of ALT"
        return ix

    def make_extend_lookup_table_ix(self, ident: SolAltID, account_key_list: Sequence[SolPubKey]) -> SolTxIx:
        assert len(account_key_list), "No accounts for ALT extending"
        return _sys.extend_lookup_table(
            _sys.ExtendLookupTableParams(
                payer_address=self._owner,
                lookup_table_address=ident.address,
                authority_address=self._owner,
                new_addresses=list(account_key_list),
            )
        )

    def make_deactivate_lookup_table_ix(self, ident: SolAltID) -> SolTxIx:
        return _sys.deactivate_lookup_table(
            _sys.DeactivateLookupTableParams(
                lookup_table_address=ident.address,
                authority_address=self._owner,
            )
        )

    def make_close_lookup_table_ix(self, ident: SolAltID) -> SolTxIx:
        return _sys.close_lookup_table(
            _sys.CloseLookupTableParams(
                lookup_table_address=ident.address,
                authority_address=self._owner,
                recipient_address=self._owner,
            )
        )


class SolRpcAltInfo:
    _Layout = Struct(
        "type" / Int32ul,  # noqa
        "deactivation_slot" / Int64ul,  # noqa
        "last_extended_slot" / Int64ul,  # noqa
        "last_extended_slot_start_index" / Int8ul,  # noqa
        "has_authority" / Int8ul,  # noqa
        "authority" / Bytes(32),  # noqa
        "padding" / Int16ul,  # noqa
    )
    _empty_slot = 2**64 - 1

    def __init__(self, address: SolPubKey, data: bytes | None) -> None:
        self._addr = address
        self._deactivation_slot: int | None = 0
        self._owner = SolPubKey.default()
        self._acct_key_list: tuple[SolPubKey, ...] = tuple()

        if len(data) < self._Layout.sizeof():
            return

        layout = self._Layout.parse(data)
        offset = self._Layout.sizeof()

        if (len(data) - offset) % SolPubKey.LENGTH:
            return
        addr_len = math.ceil((len(data) - offset) / SolPubKey.LENGTH)
        acct_key_list = list()
        for _ in range(addr_len):
            key = SolPubKey.from_bytes(data[offset : offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH
            acct_key_list.append(key)

        if layout.has_authority:
            self._owner = SolPubKey.from_bytes(layout.authority)

        self._deactivation_slot = None if layout.deactivation_slot == self._empty_slot else layout.deactivation_slot
        self._acct_key_list = tuple(acct_key_list)

    @classmethod
    def from_bytes(cls, address: SolPubKey, data: bytes | None) -> Self:
        return cls(address, data)

    @property
    def is_empty(self) -> bool:
        return not self._acct_key_list

    @property
    def address(self) -> SolPubKey:
        return self._addr

    @property
    def owner(self) -> SolPubKey:
        return self._owner

    @property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return self._acct_key_list

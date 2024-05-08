from __future__ import annotations

import asyncio
from typing import Sequence, Final

from typing_extensions import Self

from .client import SolClient
from ..solana.alt_info import SolAltInfo
from ..solana.alt_program import SolAltProg
from ..solana.cb_program import SolCbProg
from ..solana.commit_level import SolCommit
from ..solana.errors import SolAltContentError
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana.transaction_legacy import SolLegacyTx


class SolAltTxSet:
    def __init__(self, create_alt_tx_list: Sequence[SolLegacyTx], extend_alt_tx_list: Sequence[SolLegacyTx]) -> None:
        self.create_alt_tx_list = list(create_alt_tx_list)
        self.extend_alt_tx_list = list(extend_alt_tx_list)

    def extend(self, tx_list: SolAltTxSet) -> Self:
        self.create_alt_tx_list.extend(tx_list.create_alt_tx_list)
        self.extend_alt_tx_list.extend(tx_list.extend_alt_tx_list)
        return self

    def __len__(self) -> int:
        return len(self.create_alt_tx_list) + len(self.extend_alt_tx_list)

    def clear(self) -> None:
        self.create_alt_tx_list.clear()
        self.extend_alt_tx_list.clear()


class SolAltTxBuilder:
    _create_name: Final[str] = "CreateLookupTable"
    _extend_name: Final[str] = "ExtendLookupTable"

    def __init__(self, sol_client: SolClient, owner: SolPubKey, cu_price: int) -> None:
        self._sol_client = sol_client
        self._alt_prog = SolAltProg(owner)
        self._cb_prog = SolCbProg()
        self._cu_price = cu_price
        self._recent_slot: int | None = None

    async def _get_recent_slot(self) -> int:
        while True:
            recent_slot = await self._sol_client.get_slot(SolCommit.Finalized)
            if recent_slot == self._recent_slot:
                await asyncio.sleep(0.1)  # To make unique address for Address Lookup Table
                continue
            self._recent_slot = recent_slot
            return recent_slot

    @property
    def tx_name_list(self) -> tuple[str, ...]:
        return tuple([self._create_name, self._extend_name])

    async def build_alt_info(self, legacy_tx: SolLegacyTx) -> SolAltInfo:
        recent_slot = await self._get_recent_slot()
        return self._build_alt_info(legacy_tx, recent_slot)

    def build_fake_alt_info(self, legacy_tx: SolLegacyTx, recent_slot=10) -> SolAltInfo:
        return self._build_alt_info(legacy_tx, recent_slot)

    def _build_alt_info(self, legacy_tx: SolLegacyTx, recent_slot: int) -> SolAltInfo:
        alt_ident = self._alt_prog.derive_lookup_table_address(recent_slot)
        alt_info = SolAltInfo.from_legacy_tx(alt_ident, legacy_tx)
        return alt_info

    def build_alt_tx_set(self, alt_info: SolAltInfo) -> SolAltTxSet:
        is_alt_exist = alt_info.is_exist

        # Tx to create an Address Lookup Table
        create_alt_tx_list: list[SolLegacyTx] = list()
        if not is_alt_exist:
            ix_list = list()
            if self._cu_price:
                ix_list.append(self._cb_prog.make_cu_price_ix(self._cu_price))
            ix_list.append(self._alt_prog.make_create_lookup_table_ix(alt_info.ident))

            create_alt_tx = SolLegacyTx(name=self._create_name, ix_list=tuple(ix_list))
            create_alt_tx_list.append(create_alt_tx)

        # List of accounts to write to the Address Lookup Table
        acct_list = list(alt_info.new_account_key_set)

        # List of txs to extend the Address Lookup Table
        extend_alt_tx_list: list[SolLegacyTx] = list()
        max_tx_acct_cnt = SolAltProg.MaxTxAccountCnt
        while len(acct_list):
            acct_list_part, acct_list = acct_list[:max_tx_acct_cnt], acct_list[max_tx_acct_cnt:]
            ix_list = list()
            if self._cu_price:
                ix_list.append(self._cb_prog.make_cu_price_ix(self._cu_price))
            ix_list.append(self._alt_prog.make_extend_lookup_table_ix(alt_info.ident, acct_list_part))
            tx = SolLegacyTx(name=self._extend_name, ix_list=ix_list)
            extend_alt_tx_list.append(tx)

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        if not is_alt_exist:
            create_alt_tx_list[0].add(extend_alt_tx_list[0].ix_list[-1])
            extend_alt_tx_list = extend_alt_tx_list[1:]

        return SolAltTxSet(create_alt_tx_list=create_alt_tx_list, extend_alt_tx_list=extend_alt_tx_list)

    @classmethod
    def build_prep_alt_list(cls, alt_tx_set: SolAltTxSet) -> list[list[SolTx]]:
        tx_list_list: list[list[SolTx]] = list()

        if alt_tx_set.create_alt_tx_list:
            tx_list_list.append(alt_tx_set.create_alt_tx_list)

        if alt_tx_set.extend_alt_tx_list:
            tx_list_list.append(alt_tx_set.extend_alt_tx_list)

        return tx_list_list

    async def update_alt_info(self, alt_info_list: SolAltInfo | Sequence[SolAltInfo]) -> None:
        # Account keys in Account Lookup Table can be reordered, because ExtendLookup txs can be committed in any order
        if isinstance(alt_info_list, SolAltInfo):
            alt_info_list = tuple([alt_info_list])

        for alt_info in alt_info_list:
            alt_acct_info = await self._sol_client.get_alt_account(alt_info.address)
            if alt_acct_info is None:
                raise SolAltContentError(alt_info.address, "cannot read lookup table")
            alt_info.update_from_account(alt_acct_info)

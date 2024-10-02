from __future__ import annotations

import asyncio
import logging
from typing import Sequence, Final

from typing_extensions import Self

from .client import SolClient
from ..config.constants import ONE_BLOCK_SEC
from ..solana.alt_info import SolAltInfo
from ..solana.alt_program import SolAltProg, SolAltAccountInfo
from ..solana.cb_program import SolCbProg
from ..solana.commit_level import SolCommit
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana.transaction_legacy import SolLegacyTx
from ..utils.cached import reset_cached_method

_LOG = logging.getLogger(__name__)


class SolAltTxSet:
    def __init__(self, create_alt_tx_list: Sequence[SolLegacyTx], extend_alt_tx_list: Sequence[SolLegacyTx]) -> None:
        self._create_alt_tx_list = list(create_alt_tx_list)
        self._extend_alt_tx_list = list(extend_alt_tx_list)

    def extend(self, tx_list: SolAltTxSet) -> Self:
        self._built_tx_list_list.reset_cache(self)
        self._create_alt_tx_list.extend(tx_list._create_alt_tx_list)
        self._extend_alt_tx_list.extend(tx_list._extend_alt_tx_list)
        return self

    def __len__(self) -> int:
        return len(self._create_alt_tx_list) + len(self._extend_alt_tx_list)

    def clear(self) -> None:
        self._built_tx_list_list.reset_cache(self)
        self._create_alt_tx_list.clear()
        self._extend_alt_tx_list.clear()

    @property
    def tx_list_list(self) -> list[list[SolTx]]:
        return self._built_tx_list_list()

    @reset_cached_method
    def _built_tx_list_list(self) -> list[list[SolTx]]:
        tx_list_list: list[list[SolTx]] = list()

        if self._create_alt_tx_list:
            tx_list_list.append(self._create_alt_tx_list)

        if self._extend_alt_tx_list:
            tx_list_list.append(self._extend_alt_tx_list)

        return tx_list_list


class SolAltTxBuilder:
    _create_name: Final[str] = "CreateLookupTable"
    _extend_name: Final[str] = "ExtendLookupTable"
    _wait_sec: Final[float] = max(ONE_BLOCK_SEC / 5, 0.05)
    _wait_period: Final[int] = min(int(3 * ONE_BLOCK_SEC / _wait_sec), 1)

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
                await asyncio.sleep(ONE_BLOCK_SEC / 4)  # To make unique address for Address Lookup Table
                continue
            self._recent_slot = recent_slot
            return recent_slot

    @property
    def tx_name_list(self) -> tuple[str, ...]:
        return tuple([self._create_name, self._extend_name])

    async def build_alt(self, legacy_tx: SolLegacyTx, ignore_key_list: Sequence[SolPubKey]) -> SolAltInfo:
        recent_slot = await self._get_recent_slot()
        return self._build_alt(legacy_tx, recent_slot, ignore_key_list)

    def build_fake_alt(
        self,
        legacy_tx: SolLegacyTx,
        ignore_key_list: Sequence[SolPubKey],
        recent_slot=10,
    ) -> SolAltInfo:
        return self._build_alt(legacy_tx, recent_slot, ignore_key_list)

    def _build_alt(
        self,
        legacy_tx: SolLegacyTx,
        recent_slot: int,
        ignore_key_list: Sequence[SolPubKey],
    ) -> SolAltInfo:
        alt_ident = self._alt_prog.derive_alt_address(recent_slot)
        return SolAltInfo.from_legacy_tx(alt_ident, legacy_tx, ignore_key_list)

    def build_alt_tx_set(self, alt: SolAltInfo) -> SolAltTxSet:
        is_alt_exist = alt.is_exist

        # Tx to create an Address Lookup Table
        create_alt_tx_list: list[SolLegacyTx] = list()
        if not is_alt_exist:
            ix_list = list()
            if self._cu_price:
                ix_list.append(self._cb_prog.make_cu_price_ix(self._cu_price))
            ix_list.append(self._cb_prog.make_cu_limit_ix(3_400))
            ix_list.append(self._alt_prog.make_create_alt_ix(alt.ident))

            create_alt_tx = SolLegacyTx(name=self._create_name, ix_list=tuple(ix_list))
            create_alt_tx_list.append(create_alt_tx)

        # List of accounts to write to the Address Lookup Table
        acct_list = list(alt.new_account_key_set)

        # List of txs to extend the Address Lookup Table
        extend_alt_tx_list: list[SolLegacyTx] = list()
        max_tx_acct_cnt = SolAltProg.MaxTxAccountCnt
        while acct_list:
            acct_list_part, acct_list = acct_list[:max_tx_acct_cnt], acct_list[max_tx_acct_cnt:]
            ix_list = list()
            if self._cu_price:
                ix_list.append(self._cb_prog.make_cu_price_ix(self._cu_price))
            ix_list.append(self._cb_prog.make_cu_limit_ix(2_200))
            ix_list.append(self._alt_prog.make_extend_alt_ix(alt.ident, acct_list_part))
            tx = SolLegacyTx(name=self._extend_name, ix_list=ix_list)
            extend_alt_tx_list.append(tx)

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        if not is_alt_exist:
            create_alt_tx_list[0].add(extend_alt_tx_list[0].ix_list[-1])
            extend_alt_tx_list = extend_alt_tx_list[1:]

        return SolAltTxSet(create_alt_tx_list=create_alt_tx_list, extend_alt_tx_list=extend_alt_tx_list)

    async def update_alt(self, alt_list: SolAltInfo | Sequence[SolAltInfo]) -> None:
        # Account keys in Account Lookup Table can be reordered, because ExtendLookup txs can be committed in any order
        if isinstance(alt_list, SolAltInfo):
            alt_list = tuple([alt_list])

        for alt in alt_list:
            alt_acct: SolAltAccountInfo | None = None

            for _ in range(self._wait_period):
                alt_acct, last_slot = await asyncio.gather(
                    self._sol_client.get_alt_account(alt.address),
                    self._sol_client.get_slot(SolCommit.Confirmed),
                )

                if alt_acct.is_exist and (alt_acct.last_extended_slot < last_slot):
                    break

                await asyncio.sleep(self._wait_sec)

            if not alt_acct.is_exist:
                _LOG.debug("ALT %s doesn't exist", alt.address)
            else:
                _LOG.debug("ALT %s contains %s accounts", alt.address, len(alt_acct.account_key_list))
            alt.update_from_account(alt_acct)

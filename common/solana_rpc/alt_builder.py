from __future__ import annotations

import logging
import time
from typing import Sequence, Final, ClassVar

from typing_extensions import Self

from .client import SolClient
from .ws_client import SolWatchAccountSession, SolWatchSlotSession
from ..config.config import Config
from ..config.constants import MIN_FINALIZE_SEC
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
    def tx_list_list(self) -> Sequence[Sequence[SolTx]]:
        return self._built_tx_list_list()

    @reset_cached_method
    def _built_tx_list_list(self) -> Sequence[Sequence[SolTx]]:
        tx_list_list: list[list[SolTx]] = list()

        if self._create_alt_tx_list:
            tx_list_list.append(self._create_alt_tx_list)

        if self._extend_alt_tx_list:
            tx_list_list.append(self._extend_alt_tx_list)

        return tx_list_list


class SolAltTxBuilder:
    _create_name: Final[str] = "CreateLookupTable"
    _extend_name: Final[str] = "ExtendLookupTable"
    _wait_nsec: Final[int] = int(MIN_FINALIZE_SEC * 1e9)
    _recent_slot_dict: ClassVar[dict[SolPubKey, int]] = dict()

    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        slot_session: SolWatchSlotSession,
        owner: SolPubKey,
        cu_price: int,
    ) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._slot_session = slot_session
        self._alt_prog = SolAltProg(owner)
        self._cb_prog = SolCbProg()
        self._cu_price = cu_price

    @property
    def _new_slot(self) -> int:
        return self._slot_session.finalized_slot

    async def _get_recent_slot(self) -> int:
        while (new_slot := self._new_slot) <= (last_slot := self._recent_slot_dict.get(self._alt_prog.payer, 0)):
            await self._slot_session.wait_for_slot(last_slot + 1, SolCommit.Finalized)

        self._recent_slot_dict[self._alt_prog.payer] = new_slot
        return new_slot

    @property
    def tx_name_list(self) -> Sequence[str]:
        return tuple([self._create_name, self._extend_name])

    def build_fake_alt(self, legacy_tx: SolLegacyTx, *, recent_slot=10) -> SolAltInfo:
        alt_ident = self._alt_prog.derive_alt_address(recent_slot)
        return SolAltInfo.from_legacy_tx(alt_ident, legacy_tx, is_fake=True)

    @staticmethod
    def rebuild_to_small_alt(alt: SolAltInfo) -> SolAltInfo:
        return alt.clone(account_limit=SolAltProg.MaxTxAccountCnt)

    async def rebuild_to_real_alt(self, alt: SolAltInfo) -> SolAltInfo:
        recent_slot = await self._get_recent_slot()
        alt_ident = self._alt_prog.derive_alt_address(recent_slot)
        return alt.clone(ident=alt_ident, is_fake=False)

    @staticmethod
    def can_merge_alt(dst_alt: SolAltInfo, src_alt: SolAltInfo) -> bool:
        return len(dst_alt.account_key_list) + len(src_alt.account_key_list) < SolAltProg.MaxAltAccountCnt

    def build_alt_tx_set(self, alt: SolAltInfo) -> SolAltTxSet:
        is_alt_exist = alt.is_exist

        # Tx to create an Address Lookup Table
        create_alt_tx_list: list[SolLegacyTx] = list()
        if not is_alt_exist:
            ix_list = tuple(
                [
                    self._cb_prog.make_cu_price_ix(self._cu_price),
                    self._cb_prog.make_cu_limit_ix(self._alt_prog.CuLimitCreate),
                    self._alt_prog.make_create_alt_ix(alt.ident),
                ]
            )
            create_alt_tx = SolLegacyTx(name=self._create_name, ix_list=ix_list)
            create_alt_tx_list.append(create_alt_tx)

        # List of accounts to write to the Address Lookup Table
        acct_list = list(alt.new_account_key_set)

        # List of txs to extend the Address Lookup Table
        extend_alt_tx_list: list[SolLegacyTx] = list()
        max_tx_acct_cnt = SolAltProg.MaxTxAccountCnt
        while acct_list:
            acct_list_part, acct_list = acct_list[:max_tx_acct_cnt], acct_list[max_tx_acct_cnt:]
            ix_list = tuple(
                [
                    self._cb_prog.make_cu_price_ix(self._cu_price),
                    self._cb_prog.make_cu_limit_ix(self._alt_prog.CuLimitExtend),
                    self._alt_prog.make_extend_alt_ix(alt.ident, acct_list_part),
                ]
            )
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

        new_alt_dict = {alt.address: alt for alt in alt_list if alt.new_account_key_set}
        await self._update_new_alt(new_alt_dict)

        old_alt_dict = {alt.address: alt for alt in alt_list if not alt.new_account_key_set}
        await self._update_old_alt(old_alt_dict)

    async def _update_new_alt(self, new_alt_dict: dict[SolPubKey, SolAltInfo]) -> None:
        if not (new_addr_set := set(new_alt_dict.keys())):
            return

        async with SolWatchAccountSession(self._cfg, self._sol_client, init_account=True) as acct_session:
            for addr in new_addr_set:
                await acct_session.subscribe_account(addr)

            # wait for confirmation of all ALTs
            #  it is required for solana simulations
            now_nsec = time.monotonic_ns()
            stop_time_nsec = now_nsec + self._wait_nsec
            last_extended_slot = 0
            while (stop_time_nsec > now_nsec) and new_addr_set:
                await acct_session.update(timeout_nsec=(stop_time_nsec - now_nsec))
                addr_list = acct_session.pop_changed_key_list()

                for addr in addr_list:
                    if acct := acct_session.get_account(addr):
                        new_addr_set.remove(addr)
                        alt_acct = SolAltAccountInfo.from_account_nothrow(acct)
                        last_extended_slot = max(last_extended_slot, alt_acct.last_extended_slot)
                        new_alt_dict[addr].update_from_account(alt_acct)
                        # _LOG.debug("ALT %s contains %s accounts", addr, len(alt_acct.account_key_list))

                now_nsec = time.monotonic_ns()

        # for addr in new_addr_set:
        #     _LOG.debug("ALT %s doesn't exist", addr)

        await self._slot_session.wait_for_slot(last_extended_slot + 1, SolCommit.Processed)

    async def _update_old_alt(self, old_alt_dict: dict[SolPubKey, SolAltInfo]) -> None:
        if not (addr_list := tuple(old_alt_dict.keys())):
            return

        acct_list = await self._sol_client.get_account_list(addr_list)
        for addr, acct in zip(addr_list, acct_list):
            alt_acct = SolAltAccountInfo.from_account_nothrow(acct)
            old_alt_dict[addr].update_from_account(alt_acct)

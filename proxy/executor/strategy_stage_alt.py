from __future__ import annotations

import logging
from typing import Sequence, ClassVar

from common.neon.neon_program import NeonProg
from common.solana.alt_info import SolAltInfo
from common.solana.alt_program import SolAltProg
from common.solana.errors import SolTxSizeError
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_v0 import SolV0Tx
from common.solana_rpc.alt_builder import SolAltTxBuilder
from .strategy_base import BaseTxPrepStage, SolTxCfg

_LOG = logging.getLogger(__name__)


class AltTxPrepStage(BaseTxPrepStage):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._legacy_tx: SolLegacyTx | None = None
        self._last_alt: SolAltInfo | None = None
        self._alt_dict: dict[SolPubKey, SolAltInfo] = dict()
        self._alt_builder = SolAltTxBuilder(
            self._cfg,
            self._sol_client,
            self._slot_session,
            self._ctx.sol_payer,
            self._cu_price,
        )

    def get_tx_name_list(self) -> Sequence[str]:
        return self._alt_builder.tx_name_list

    def set_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        self._legacy_tx = legacy_tx

    async def build_tx_list(self) -> Sequence[Sequence[SolTx]]:
        self._last_alt = None
        self._alt_dict.clear()

        actual_alt = self._alt_builder.build_fake_alt(self._legacy_tx)
        small_alt = self._alt_builder.rebuild_to_small_alt(actual_alt)
        if self._tx_has_valid_size(self._legacy_tx, tuple([small_alt])):
            actual_alt = small_alt

        alt_list = await self._filter_valid_alt_list(actual_alt)
        if self._alt_dict and self._tx_has_valid_size(self._legacy_tx, alt_list):
            return list()

        actual_alt = await self._extend_alt(actual_alt, alt_list)
        alt_tx_set = self._alt_builder.build_ext_alt_tx_set(actual_alt)

        self._alt_dict[actual_alt.address] = actual_alt
        self._ctx.add_alt_id(actual_alt.ident)

        self._last_alt = actual_alt
        return alt_tx_set.tx_list_list

    async def prep_before_exec(self) -> bool:
        return await self._has_valid_tx_size()

    def build_tx(self, legacy_tx: SolLegacyTx, alt_list: Sequence[SolAltInfo] | None = None) -> SolV0Tx:
        if not alt_list:
            alt_list = self._alt_list
        return SolV0Tx(name=legacy_tx.name, ix_list=legacy_tx.ix_list, alt_list=alt_list)

    def validate_v0_tx_size(self, legacy_tx: SolLegacyTx) -> bool:
        test_alt = self._alt_builder.build_fake_alt(legacy_tx)  # <- SolAltError
        self.build_tx(legacy_tx, tuple([test_alt])).validate(SolSigner.fake())  # <- SolTxSize?
        return True

    # protected:

    async def _has_valid_tx_size(self) -> bool:
        await self._alt_builder.update_alt(self._alt_list)
        if not self._tx_has_valid_size(self._legacy_tx):
            # _LOG.debug("ALT %s isn't synced yet")
            return False
        return True

    @property
    def _alt_list(self) -> list[SolAltInfo]:
        return list(self._alt_dict.values())

    def _tx_has_valid_size(self, legacy_tx: SolLegacyTx, alt_list: Sequence[SolAltInfo] | None = None) -> bool:
        try:
            with self._ctx.test_mode():
                self.build_tx(legacy_tx, alt_list).validate(SolSigner.fake())
            return True
        except SolTxSizeError:
            return False

    async def _filter_valid_alt_list(self, actual_alt: SolAltInfo) -> list[SolAltInfo]:
        new_alt_list = tuple([SolAltInfo(ident) for ident in self._ctx.alt_id_list])
        await self._alt_builder.update_alt(new_alt_list)
        new_alt_list = list(filter(lambda x: x.is_exist, new_alt_list))

        alt_list: list[SolAltInfo] = list()
        for alt in new_alt_list:
            if actual_alt.remove_account_key_list(alt.account_key_list):
                self._alt_dict[alt.address] = alt
                alt_list.append(alt)

        return alt_list

    async def _extend_alt(self, actual_alt: SolAltInfo, alt_list: Sequence[SolAltInfo]) -> SolAltInfo:
        for alt in alt_list:
            if alt.owner != self._ctx.sol_payer:
                continue
            elif not self._alt_builder.can_merge_alt(alt, actual_alt):
                continue

            alt.add_account_key_list(actual_alt.account_key_list)
            return alt

        if actual_alt.is_fake:
            return await self._alt_builder.rebuild_to_real_alt(actual_alt)
        return actual_alt


def alt_strategy(cls):
    class AltStrategy(cls):
        name: ClassVar[str] = "ALT+" + cls.name

        def __init__(self, *args, **kwargs) -> None:
            cls.__init__(self, *args, **kwargs)
            self._alt_stage = AltTxPrepStage(*args, **kwargs)
            self._prep_stage_list.append(self._alt_stage)

        async def prep_before_exec(self) -> bool:
            # It isn't critical to pass a fake signer.
            # The signer isn't included in ALT, so the fake signer will be excluded from the ALT lists,
            #  and in the final version of tx it will be replaced with the real signer
            self._alt_stage.set_legacy_tx(self._build_test_legacy_tx())
            return await cls.prep_before_exec(self)

        async def _validate(self) -> bool:
            return self._validate_account_list_len() and await cls._validate(self)

        def _validate_account_list_len(self) -> bool:
            len_account_meta_list = self._ctx.len_account_meta_list + NeonProg.BaseAccountCnt
            if len_account_meta_list < SolAltProg.MaxTxAccountCnt:
                self._validation_error_msg = (
                    f"Number of accounts {len_account_meta_list} is less than {SolAltProg.MaxTxAccountCnt}"
                )
                return False
            return True

        def _validate_tx_size(self) -> bool:
            return self._alt_stage.validate_v0_tx_size(self._build_test_legacy_tx())

        def _build_test_legacy_tx(self) -> SolLegacyTx:
            with self._ctx.test_mode():
                tx_cfg = self._init_sol_tx_cfg()
                ix = cls._build_tx_ix(self, tx_cfg)
                return cls._build_cu_tx(ix, tx_cfg)

        def _build_cu_tx(self, ix: SolTxIx, tx_cfg: SolTxCfg) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cu_tx(ix, tx_cfg))

    return AltStrategy

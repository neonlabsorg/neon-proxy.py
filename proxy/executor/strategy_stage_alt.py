from __future__ import annotations

import logging
from typing import Sequence, ClassVar

from common.neon.neon_program import NeonProg
from common.solana.alt_info import SolAltInfo
from common.solana.alt_program import SolAltProg
from common.solana.errors import SolTxSizeError, SolAltContentError
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
        self._alt_builder = SolAltTxBuilder(self._ctx.sol_client, self._ctx.payer, self._ctx.cfg.simple_cu_price)

    def get_tx_name_list(self) -> tuple[str, ...]:
        return self._alt_builder.tx_name_list

    def set_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        self._legacy_tx = legacy_tx

    async def build_tx_list(self) -> list[list[SolTx]]:
        self._last_alt = None
        self._alt_dict.clear()
        actual_alt = await self._alt_builder.build_alt(self._legacy_tx, self._ctx.ro_address_list)

        alt_list = await self._filter_alt_list(actual_alt)
        if self._alt_dict and self._tx_has_valid_size(self._legacy_tx):
            return list()

        actual_alt = self._extend_alt(actual_alt, alt_list)
        alt_tx_set = self._alt_builder.build_alt_tx_set(actual_alt)

        self._add_alt(actual_alt)
        self._ctx.add_alt_id(actual_alt.ident)

        self._last_alt = actual_alt
        return alt_tx_set.tx_list_list

    async def update_after_emulate(self) -> None:
        last_alt = self._last_alt
        await self._alt_builder.update_alt(self._alt_list)
        if not self._tx_has_valid_size(self._legacy_tx):
            raise SolAltContentError(last_alt.address, "is not synced yet")

    def build_tx(self, legacy_tx: SolLegacyTx, alt_list: list[SolAltInfo] = None) -> SolV0Tx:
        if not alt_list:
            alt_list = self._alt_list
        return SolV0Tx(name=legacy_tx.name, ix_list=legacy_tx.ix_list, alt_list=alt_list)

    def validate_v0_tx_size(self, legacy_tx: SolLegacyTx) -> bool:
        test_alt = self._alt_builder.build_fake_alt(legacy_tx, self._ctx.ro_address_list)  # <- SolAltError
        self.build_tx(legacy_tx, [test_alt]).validate(SolSigner.fake())  # <- SolTxSize?
        return True

    # protected:

    @property
    def _alt_list(self) -> list[SolAltInfo]:
        return list(self._alt_dict.values())

    def _tx_has_valid_size(self, legacy_tx: SolLegacyTx) -> bool:
        try:
            with self._ctx.test_mode():
                self.build_tx(legacy_tx).validate(SolSigner.fake())
            return True
        except SolTxSizeError:
            return False

    async def _filter_alt_list(self, actual_alt: SolAltInfo) -> list[SolAltInfo]:
        alt_list: list[SolAltInfo] = list()
        for alt_id in self._ctx.alt_id_list:
            alt = SolAltInfo(alt_id)
            try:
                # update one by one, if one of ALTs has problems it shouldn't affect others
                await self._alt_builder.update_alt(alt)
                if not alt.is_exist:
                    _LOG.debug("skip not-exist ALT %s", alt.address)
                    continue

                alt_list.append(alt)
                if actual_alt.remove_account_key_list(alt.account_key_list):
                    self._add_alt(alt)

            except BaseException as exc:
                _LOG.debug("skip ALT %s", alt_id.address, exc_info=exc)

        return alt_list

    def _add_alt(self, alt: SolAltInfo) -> None:
        if alt.address in self._alt_dict:
            return

        self._alt_dict[alt.address] = alt
        if alt.is_exist:
            _LOG.debug("use existing ALT %s", alt.address)
        else:
            _LOG.debug("create new ALT %s", alt.address)

    def _extend_alt(self, actual_alt: SolAltInfo, alt_list: Sequence[SolAltInfo]) -> SolAltInfo:
        for alt in alt_list:
            if alt.owner != self._ctx.payer:
                continue
            elif len(actual_alt.account_key_list) + len(alt.account_key_list) >= SolAltProg.MaxAltAccountCnt:
                continue

            alt.add_account_key_list(actual_alt.account_key_list)
            return alt

        return actual_alt


def alt_strategy(cls):
    class AltStrategy(cls):
        name: ClassVar[str] = "ALT+" + cls.name

        def __init__(self, *args, **kwargs) -> None:
            cls.__init__(self, *args, **kwargs)
            self._alt_stage = AltTxPrepStage(*args, **kwargs)
            self._prep_stage_list.append(self._alt_stage)

        async def prep_before_emulate(self) -> bool:
            # it isn't critical to pass a fake signer, because signer isn't included into ALT
            #  so the fake signer will be excluded from the ALT lists,
            #  and in the final version of tx it will be replaced with the real signer
            with self._ctx.test_mode():
                self._alt_stage.set_legacy_tx(self._build_legacy_tx(SolTxCfg.fake()))
            return await cls.prep_before_emulate(self)

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
            with self._ctx.test_mode():
                return self._alt_stage.validate_v0_tx_size(self._build_legacy_tx(SolTxCfg.fake()))

        def _build_legacy_tx(self, tx_cfg: SolTxCfg) -> SolLegacyTx:
            return cls._build_tx(self, tx_cfg)

        def _build_tx(self, tx_cfg: SolTxCfg) -> SolV0Tx:
            return self._alt_stage.build_tx(self._build_legacy_tx(tx_cfg))

        def _build_cancel_tx(self, tx_cfg: SolTxCfg) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cancel_tx(self, tx_cfg))

    return AltStrategy

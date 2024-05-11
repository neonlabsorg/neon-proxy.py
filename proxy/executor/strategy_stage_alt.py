from __future__ import annotations

import logging
from typing import Sequence

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
from .strategy_base import BaseTxPrepStage

_LOG = logging.getLogger(__name__)


class AltTxPrepStage(BaseTxPrepStage):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._legacy_tx: SolLegacyTx | None = None
        self._last_alt_info: SolAltInfo | None = None
        self._alt_info_dict: dict[SolPubKey, SolAltInfo] = dict()
        self._alt_builder = SolAltTxBuilder(self._ctx.sol_client, self._ctx.payer, self._ctx.cfg.simple_cu_price)

    def get_tx_name_list(self) -> tuple[str, ...]:
        return self._alt_builder.tx_name_list

    def set_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        self._legacy_tx = legacy_tx

    async def build_tx_list(self) -> list[list[SolTx]]:
        self._last_alt_info = None
        self._alt_info_dict.clear()
        actual_alt_info = await self._alt_builder.build_alt_info(self._legacy_tx)

        alt_info_list = await self._filter_alt_info_list(actual_alt_info)
        if (len(self._alt_info_dict) > 0) and self._tx_has_valid_size(self._legacy_tx):
            return list()

        actual_alt_info = self._extend_alt_info(actual_alt_info, alt_info_list)
        alt_tx_set = self._alt_builder.build_alt_tx_set(actual_alt_info)

        self._add_alt_info(actual_alt_info)
        self._ctx.add_alt_id(actual_alt_info.ident)

        self._last_alt_info = actual_alt_info
        return self._alt_builder.build_prep_alt_list(alt_tx_set)

    async def update_after_emulate(self) -> None:
        last_alt_info = self._last_alt_info
        await self._alt_builder.update_alt_info(self._alt_info_list)
        if not self._tx_has_valid_size(self._legacy_tx):
            raise SolAltContentError(last_alt_info.address, "is not synced yet")

    def build_tx(self, legacy_tx: SolLegacyTx, alt_info_list: list[SolAltInfo] = None) -> SolV0Tx:
        if not alt_info_list:
            alt_info_list = self._alt_info_list
        return SolV0Tx(name=legacy_tx.name, ix_list=legacy_tx.ix_list, alt_info_list=alt_info_list)

    def validate_v0_tx_size(self, legacy_tx: SolLegacyTx) -> bool:
        test_alt_info = self._alt_builder.build_fake_alt_info(legacy_tx)  # <- SolAltError
        self.build_tx(legacy_tx, [test_alt_info]).validate(SolSigner.fake())  # <- SolTxSize?
        return True

    # protected:

    @property
    def _alt_info_list(self) -> list[SolAltInfo]:
        return list(self._alt_info_dict.values())

    def _tx_has_valid_size(self, legacy_tx: SolLegacyTx) -> bool:
        try:
            with self._ctx.test_mode():
                self.build_tx(legacy_tx).validate(SolSigner.fake())
            return True
        except SolTxSizeError:
            return False

    async def _filter_alt_info_list(self, actual_alt_info: SolAltInfo) -> list[SolAltInfo]:
        alt_info_list: list[SolAltInfo] = list()
        for alt_address in self._ctx.alt_id_list:
            alt_info = SolAltInfo(alt_address)
            try:
                # update one by one, if one of ALTs has problems it shouldn't affect others
                await self._alt_builder.update_alt_info(alt_info)
                alt_info_list.append(alt_info)

                if actual_alt_info.remove_account_key_list(tuple(alt_info.account_key_set)):
                    self._add_alt_info(alt_info)

            except BaseException as exc:
                _LOG.debug("skip ALT %s", alt_address.address, exc_info=exc)

        return alt_info_list

    def _add_alt_info(self, alt_info: SolAltInfo) -> None:
        if alt_info.address in self._alt_info_dict:
            return

        self._alt_info_dict[alt_info.address] = alt_info
        if alt_info.is_exist:
            _LOG.debug("use existing ALT %s", alt_info.address)
        else:
            _LOG.debug("create new ALT %s", alt_info.address)

    def _extend_alt_info(self, actual_alt_info: SolAltInfo, alt_info_list: Sequence[SolAltInfo]) -> SolAltInfo:
        for alt_info in alt_info_list:
            if alt_info.owner != self._ctx.payer:
                continue
            elif len(actual_alt_info.account_key_set) + len(alt_info.account_key_set) >= SolAltProg.MaxAltAccountCnt:
                continue

            alt_info.add_account_key_list(tuple(actual_alt_info.account_key_set))
            return alt_info

        return actual_alt_info


def alt_strategy(cls):
    class AltStrategy(cls):
        name = "ALT+" + cls.name

        def __init__(self, *args, **kwargs) -> None:
            cls.__init__(self, *args, **kwargs)
            self._alt_stage = AltTxPrepStage(*args, **kwargs)
            self._prep_stage_list.append(self._alt_stage)

        async def prep_before_emulate(self) -> bool:
            # it isn't critical to pass a fake signer, because signer isn't included into ALT
            #  so the fake signer will be excluded from the ALT lists,
            #  and in the final version of tx it will be replaced with the real signer
            with self._ctx.test_mode():
                self._alt_stage.set_legacy_tx(self._build_legacy_tx())
            return await super().prep_before_emulate()

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
                return self._alt_stage.validate_v0_tx_size(self._build_legacy_tx())

        def _build_legacy_tx(self, *, is_finalized: bool = False, step_cnt: int = 0) -> SolLegacyTx:
            return cls._build_tx(self, is_finalized=is_finalized, step_cnt=step_cnt)

        def _build_tx(self, *, is_finalized: bool = False, step_cnt: int = 0) -> SolV0Tx:
            return self._alt_stage.build_tx(self._build_legacy_tx(is_finalized=is_finalized, step_cnt=step_cnt))

        def _build_cancel_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cancel_tx(self))

    return AltStrategy

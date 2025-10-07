from __future__ import annotations

import logging
from typing import Sequence, ClassVar, Final

from common.neon.neon_program import NeonProg
from common.solana.alt_info import SolAltInfo
from common.solana.alt_program import SolAltProg
from common.solana.errors import SolTxSizeError
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_v0 import SolV0Tx
from common.solana_rpc.alt_builder import SolAltTxBuilder
from .strategy_base import BaseTxPrepStage, SolNeonTxCfg

_LOG = logging.getLogger(__name__)


class AltTxPrepStage(BaseTxPrepStage):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._legacy_tx: SolLegacyTx | None = None
        self._alt_dict: dict[SolPubKey, SolAltInfo] = dict()
        self._alt_builder = SolAltTxBuilder(
            self._cfg,
            self._sol_client,
            self._slot_session,
            self._ctx.sol_payer,
        )

    def set_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        self._legacy_tx = legacy_tx

    async def make_ix_list(self) -> Sequence[SolTxIx]:
        self._alt_dict.clear()

        actual_alt = self._alt_builder.build_fake_alt(self._legacy_tx)
        await self._filter_valid_alt_list(actual_alt)
        if self._tx_has_valid_size():
            return tuple()

        actual_alt = await self._extend_alt(actual_alt)
        self._alt_dict[actual_alt.address] = actual_alt
        self._ctx.add_alt_id(actual_alt.ident)

        return self._alt_builder.build_alt_ix_list(actual_alt)

    async def prep_execution(self) -> bool:
        await self._alt_builder.update_alt(self.alt_list)
        if not self._tx_has_valid_size():
            # _LOG.debug("ALT %s isn't synced yet")
            return False
        return True

    def make_fake_sol_neon_tx(self) -> SolV0Tx:
        actual_alt: Final = self._alt_builder.build_fake_alt(self._legacy_tx)
        return SolV0Tx(name=self._legacy_tx.name, ix_list=self._legacy_tx.ix_list, alt_list=tuple([actual_alt]))

    @property
    def alt_list(self) -> tuple[SolAltInfo]:
        return tuple(self._alt_dict.values())

    # protected:

    def _get_ix_name_list(self) -> Sequence[str]:
        return self._alt_builder.ix_name_list

    def _tx_has_valid_size(self) -> bool:
        if not (alt_list := self.alt_list):
            return False

        try:
            tx: Final = SolV0Tx(name=self._legacy_tx.name, ix_list=self._legacy_tx.ix_list, alt_list=alt_list)
            tx.validate(SolSigner.fake())
            return True
        except SolTxSizeError:
            return False

    async def _filter_valid_alt_list(self, actual_alt: SolAltInfo) -> None:
        new_alt_list = tuple([SolAltInfo(ident) for ident in self._ctx.alt_id_list])
        await self._alt_builder.update_alt(new_alt_list)

        for alt in new_alt_list:
            if alt.is_exist and actual_alt.remove_account_key_list(alt.account_key_list):
                self._alt_dict[alt.address] = alt

    async def _extend_alt(self, actual_alt: SolAltInfo) -> SolAltInfo:
        for alt in self.alt_list:
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
        Name: ClassVar[str] = "ALT+" + cls.Name

        def __init__(self, *args, **kwargs) -> None:
            cls.__init__(self, *args, **kwargs)
            self._alt_stage = AltTxPrepStage(*args, **kwargs)
            self._prep_stage_list.append(self._alt_stage)
            self._copy_legacy_tx()

        async def prep_execution(self) -> bool:
            self._copy_legacy_tx()
            return await cls.prep_execution(self)

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

        async def _send_sol_tx_list(self, ix_list: SolTxIx | Sequence[SolTxIx], tx_cfg: SolNeonTxCfg) -> bool:
            return await self._ctx.send_sol_tx_list(ix_list, cb_cfg=tx_cfg, alt_list=self._alt_stage.alt_list)

        def _copy_legacy_tx(self) -> None:
            # It isn't critical to pass a fake signer.
            # The signer isn't included in ALT, so the fake signer will be excluded from the ALT lists,
            #  and in the final version of tx it will be replaced with the real signer
            self._alt_stage.set_legacy_tx(cls._make_fake_sol_neon_tx(self))

        def _make_fake_sol_neon_tx(self) -> SolV0Tx:
            return self._alt_stage.make_fake_sol_neon_tx()

    return AltStrategy

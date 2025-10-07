import dataclasses
import logging
import typing
from typing import Sequence, Final

from .api_client import CoreApiClient
from .transaction_error_parser import SolNeonTxErrorParser
from ..config.config import Config
from ..cu_price.client import SolCuPriceClient
from ..neon.evm_log_decoder import NeonTxLogReturnInfo
from ..neon.transaction_decoder import SolNeonTxIxMetaInfo
from ..solana.alt_info import SolAltInfo
from ..solana.cb_program import SolCbProg, SolCbCfg
from ..solana.instruction import SolTxIx
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxReceiptInfo
from ..solana.transaction_v0 import SolV0Tx
from ..solana_rpc.client import SolClient
from ..solana_rpc.errors import SolCbExceededError
from ..solana_rpc.transaction_list_sender import SolTxListSender, SolTxSendState, SolTxListSigner
from ..solana_rpc.transaction_list_sender_stat import SolTxStatClient
from ..utils.cached import cached_property, reset_cached_method

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SolNeonTxSendState(SolTxSendState):
    sol_neon_ix: SolNeonTxIxMetaInfo | None = None
    neon_tx_return: NeonTxLogReturnInfo = NeonTxLogReturnInfo.default()

    @cached_property
    def has_sol_neon_ix(self) -> bool:
        return self.sol_neon_ix is not None

    @cached_property
    def is_finalized(self) -> bool:
        return not self.neon_tx_return.is_empty


class SolNeonTxListSender(SolTxListSender):
    @dataclasses.dataclass(frozen=True)
    class _SolTxIxCuInfo:
        name: str
        cu_limit: int

    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        sol_tx_signer: SolTxListSigner,
        stat_client: SolTxStatClient,
        core_api_client: CoreApiClient,
        cu_price_client: SolCuPriceClient,
    ) -> None:
        super().__init__(cfg, sol_client, sol_tx_signer, stat_client)
        self._core_api_client = core_api_client
        self._cu_price_client = cu_price_client
        self._done_ret_cnt = 0

    def clear(self) -> None:
        super().clear()
        self._done_ret_cnt = 0
        self._get_success_tx_state_list.reset_cache(self)

    @property
    def success_tx_state_list(self) -> Sequence[SolNeonTxSendState]:
        return self._get_success_tx_state_list()

    async def send_tx(
        self,
        ix_list: SolTx | SolTxIx | Sequence[SolTxIx],
        /,
        cb_cfg: SolCbCfg | None = None,
        alt_list: Sequence[SolAltInfo] = tuple(),
    ) -> bool:
        if not (ix_list := self._prep_ix_list(ix_list)):
            return False
        elif isinstance(ix_list[0], SolTx):
            return await self.send_tx_list(ix_list)

        if not cb_cfg:
            cb_cfg = SolCbCfg.default()

        # Sum the CUs for all instructions
        sum_cu_limit: Final = await self._calc_sum_cu_limit(cb_cfg, ix_list)

        # Try to execute with the calculated CUs limit, and if fails try to execute with the max CUs limit
        for cu_limit in (sum_cu_limit, cb_cfg.max_cu_limit):
            sol_tx = await self._make_sol_tx(cb_cfg.clone(cu_limit=cu_limit), ix_list, alt_list)

            try:
                return await super().send_tx_list(sol_tx)

            except SolCbExceededError:
                if cu_limit == cb_cfg.max_cu_limit:
                    raise

        return False

    async def send_tx_list(
        self,
        ix_list: SolTxIx | SolTx | Sequence[SolTxIx] | Sequence[SolTx],
        /,
        cb_cfg: SolCbCfg | None = None,
        alt_list: Sequence[SolAltInfo] = tuple(),
    ) -> bool:
        if not (ix_list := self._prep_ix_list(ix_list)):
            return False
        elif isinstance(ix_list[0], SolTx):
            return await self.send_tx_list(ix_list)

        if not cb_cfg:
            cb_cfg = SolCbCfg.default()

        # Group all instructions by name and calculate the max CUs limit for each instruction type
        cu_info_dict: Final = await self._calc_max_cu_limit(cb_cfg, ix_list)

        # Try to execute with the calculated CUs limit, and if fails try to execute with the max CUs limit
        for cu_limit in (0, cb_cfg.max_cu_limit):
            sol_tx_list: list[SolTx] = list()
            for ix in ix_list:
                tx_cu_limit = cu_limit or cu_info_dict.get(ix.name, cb_cfg.cu_limit)
                sol_tx = await self._make_sol_tx(cb_cfg.clone(cu_limit=tx_cu_limit), tuple([ix]), alt_list)
                sol_tx_list.append(sol_tx)

            try:
                return await super().send_tx_list(sol_tx_list)

            except SolCbExceededError:
                if cu_limit == cb_cfg.max_cu_limit:
                    raise

        return False

    # protected:
    #
    @staticmethod
    def _prep_ix_list(ix_list: SolTxIx | SolTx | Sequence[SolTxIx] | Sequence[SolTx]) -> Sequence[SolTxIx] | Sequence[SolTx]:
        if not ix_list:
            return tuple()
        elif isinstance(ix_list, (SolTxIx, SolTx)):
            return tuple([ix_list])
        elif not isinstance(ix_list, tuple):
            return tuple(ix_list)
        return ix_list

    async def _make_sol_tx(
        self,
        cb_cfg: SolCbCfg,
        ix_list: Sequence[SolTxIx],
        alt_list: Sequence[SolAltInfo],
    ) -> SolTx:
        cu_price: Final = await self._calc_cu_price(cb_cfg, ix_list)

        legacy_tx = SolCbProg.make_legacy_tx(cb_cfg.clone(cu_price=cu_price), ix_list)
        if not alt_list:
            return legacy_tx

        return SolV0Tx(name=legacy_tx.name, ix_list=legacy_tx.ix_list, alt_list=alt_list)

    async def _calc_sum_cu_limit(self, cb_cfg, ix_list: Sequence[SolTxIx]) -> int:
        if cb_cfg.cu_limit:
            return cb_cfg.cu_limit

        cu_info_list: Final = await self._make_cu_info_list(cb_cfg, ix_list)
        if (cu_limit := sum(map(lambda x: x.cu_limit, cu_info_list))) > cb_cfg.threshold_cu_limit:
            raise SolCbExceededError(cb_cfg.max_cu_limit)

        return cu_limit

    async def _calc_max_cu_limit(self, cb_cfg: SolCbCfg, ix_list: Sequence[SolTxIx]) -> dict[str, int]:
        if cb_cfg.cu_limit:
            return dict()

        cu_info_list: Final = await self._make_cu_info_list(cb_cfg, ix_list)
        cu_info_dict: dict[str, int] = dict()
        for ix in cu_info_list:
            if (cu_info := max(ix.cu_limit, cu_info_dict.get(ix.name, 0))) > cb_cfg.threshold_cu_limit:
                raise SolCbExceededError(cb_cfg.max_cu_limit)

            cu_info_dict[ix.name] = cu_info

        return cu_info_dict

    async def _make_cu_info_list(self, cb_cfg: SolCbCfg, ix_list: Sequence[SolTxIx]) -> Sequence[_SolTxIxCuInfo]:
        meta_list: Final = await self._core_api_client.emulate_sol_ix_list(cb_cfg, ix_list)

        cu_info_list = list()
        for ix, meta in zip(ix_list, meta_list):
            # if meta.error:
            cu_info = self._SolTxIxCuInfo(name=ix.name, cu_limit=cb_cfg.round_cu(meta.cu_consumed))
            cu_info_list.append(cu_info)

        return tuple(cu_info_list)

    async def _calc_cu_price(
        self,
        cb_cfg: SolCbCfg,
        ix_list: Sequence[SolTxIx],
    ) -> int:
        # no reason to calculate the cu-price if it's predefined
        if cb_cfg.cu_price:
            return cb_cfg.cu_price
        # no reason to calculate the cu-price if priority-fee or cu-limit isn't defined
        elif (not cb_cfg.max_priority_fee) or (not cb_cfg.cu_limit):
            fee_cfg = await self._cu_price_client.get_fee_cfg()
            return fee_cfg.def_cu_price

        rw_acct_key_list: Final = self._filter_rw_acct_key_list(ix_list)
        req_cu_price: Final = await self._cu_price_client.get_cu_price(rw_acct_key_list)
        max_cu_price: Final = cb_cfg.max_priority_fee * SolCbProg.MicroLamport // cb_cfg.cu_limit
        return max(min(req_cu_price, max_cu_price), SolCbProg.BaseCuPrice)

    @staticmethod
    def _filter_rw_acct_key_list(ix_list: Sequence[SolTxIx]) -> Sequence[SolPubKey]:
        return tuple(set([SolPubKey.from_raw(m.pubkey) for ix in ix_list for m in ix.accounts if m.is_writable]))

    @reset_cached_method
    def _get_success_tx_state_list(self) -> Sequence[SolNeonTxSendState]:
        # fmt: off
        return tuple([
            typing.cast(SolNeonTxSendState, tx_state)
            for tx_state in self._tx_state_dict.values()
            if tx_state.status != SolTxSendState.Status.ErrorReceipt
        ])
        # fmt: on

    def _decode_tx_status(self, tx: SolTx, tx_receipt: SolRpcTxReceiptInfo) -> SolTxSendState:
        status = SolTxSendState.Status

        tx_status: status
        tx_error: BaseException | None = None
        tx_error_parser = SolNeonTxErrorParser(tx, tx_receipt)

        if not (tx_return := tx_error_parser.get_neon_tx_return()).is_empty:
            tx_status = status.GoodReceipt
            self._done_ret_cnt += 1
        elif tx_error_parser.is_done_error():
            tx_status = status.GoodReceipt
            self._done_ret_cnt += 1
        elif tx_error_parser.check_if_neon_account_already_exists():
            # no exception: the neon account exists - the goal is reached
            tx_status = status.GoodReceipt
        elif tx_error := tx_error_parser.get_evm_error():
            tx_status = status.ErrorReceipt
        else:
            tx_state = super()._decode_tx_status(tx, tx_receipt)
            tx_status, tx_error = tx_state.status, tx_state.error

        # if tx_status == status.ErrorReceipt:
        #     _LOG.debug("RECEIPT: %s", tx_receipt)

        return SolNeonTxSendState(tx_status, tx, tx_receipt, tx_error, tx_error_parser.sol_neon_ix, tx_return)

    @classmethod
    def _empty_tx_status(cls, tx: SolTx, tx_status: SolTxSendState.Status) -> SolNeonTxSendState:
        return SolNeonTxSendState(tx_status, tx, None, None)

    def _is_done(self) -> bool:
        return self._done_ret_cnt > 0

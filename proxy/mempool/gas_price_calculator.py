from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from typing import Final

import pythclient.pythaccounts as _pyth_acct
import pythclient.pythclient as _pyth
import pythclient.utils as _pyth_utils

from common.config.constants import ONE_BLOCK_SEC, DEFAULT_TOKEN_NAME, CHAIN_TOKEN_NAME
from common.neon_rpc.api import EvmConfigModel, TokenModel
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import log_msg, logging_context
from .server_abc import MempoolComponent, MempoolServerAbc
from ..base.mp_api import MpGasPriceModel, MpSlotGasPriceModel, MpTokenGasPriceModel

_LOG = logging.getLogger(__name__)
_PythClient = _pyth.PythClient
_PythWatchSession = _pyth.WatchSession
_PythProdAcct = _pyth_acct.PythProductAccount
_PythPriceAcct = _pyth_acct.PythPriceAccount
_PythPriceType = _pyth_acct.PythPriceType


class MpGasPriceCalculator(MempoolComponent):
    _token_usd_precision: Final[int] = 100_000
    _update_sec: Final[int] = int(16 * ONE_BLOCK_SEC)

    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)

        self._pyth_client: _PythClient | None = None
        self._watch_session: _PythWatchSession | None = None
        self._stop_event = asyncio.Event()
        self._update_pyth_acct_task: asyncio.Task | None = None
        self._update_gas_price_task: asyncio.Task | None = None

        self._base_price_acct: _PythPriceAcct | None = None
        self._price_acct_dict: [str, _PythPriceAcct] = dict()
        self._product_list: list[_PythProdAcct] = list()
        self._price_acct_full_dict: dict[str, _PythPriceAcct] = dict()
        self._price_acct_failed_set: set[str] = set()

        self._gas_price = MpGasPriceModel(
            chain_token_price_usd=0,
            operator_fee=int(self._cfg.operator_fee * 100_000),
            cu_price=self._cfg.cu_price,
            simple_cu_price=self._cfg.simple_cu_price,
            min_wo_chain_id_acceptable_gas_price=self._cfg.min_wo_chain_id_gas_price,
            default_token=MpTokenGasPriceModel(
                chain_id=0,
                token_name=DEFAULT_TOKEN_NAME,
                token_mint=SolPubKey.default(),
                token_price_usd=0,
                is_default_token=True,
                suggested_gas_price=0,
                is_const_gas_price=True,
                min_acceptable_gas_price=0,
                min_executable_gas_price=0,
                gas_price_list=list(),
            ),
            token_dict=dict(),
        )

        _1min: Final[int] = 60  # 60 seconds

        self._recent_gas_price_cnt: Final[int] = int(_1min / self._update_sec * self._cfg.mp_gas_price_min_window)
        self._recent_gas_price_dict: dict[int, deque[MpSlotGasPriceModel]] = dict()

    async def start(self) -> None:
        self._update_pyth_acct_task = asyncio.create_task(self._update_pyth_acct_loop())
        self._update_gas_price_task = asyncio.create_task(self._update_gas_price_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._update_pyth_acct_task:
            await self._update_pyth_acct_task
        if self._update_gas_price_task:
            await self._update_gas_price_task

        if self._watch_session:
            await asyncio.gather(
                self._watch_session.unsubscribe(price_acct) for price_acct in self._price_acct_dict.values()
            )

            await asyncio.gather(
                self._watch_session.disconnect(),
                self._pyth_client.close(),
            )

    def get_gas_price(self) -> MpGasPriceModel:
        return self._gas_price

    async def _update_gas_price_loop(self) -> None:
        while True:
            sleep_sec = self._update_sec if not self._gas_price.is_empty else 1
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
            if self._stop_event.is_set():
                break

            with logging_context(ctx="mp-update-gas-price"):
                try:
                    evm_cfg = await self._server.get_evm_cfg()
                    if gas_price := await self._get_gas_price(evm_cfg):
                        self._gas_price = gas_price
                except BaseException as exc:
                    _LOG.error("error on update gas-price", exc_info=exc)

    async def _get_gas_price(self, evm_cfg: EvmConfigModel) -> MpGasPriceModel | None:
        base_price_usd = self._base_price_acct.aggregate_price_info.price if self._base_price_acct else 0.0

        token_dict: dict[str, MpTokenGasPriceModel] = dict()
        default_token: MpTokenGasPriceModel | None = None

        for token in evm_cfg.token_dict.values():
            price_acct = await self._get_price_account(token.name)
            token_gas_price = await self._calc_token_gas_price(token, base_price_usd, price_acct)
            if token_gas_price:
                token_dict[token.name] = token_gas_price
                if token_gas_price.is_default_token:
                    default_token = token_gas_price
            else:
                return None

        assert default_token is not None, "DEFAULT TOKEN NOT FOUND!"

        return MpGasPriceModel(
            chain_token_price_usd=int(base_price_usd * self._token_usd_precision),
            operator_fee=int(self._cfg.operator_fee * 100_000),
            cu_price=self._cfg.cu_price,
            simple_cu_price=self._cfg.simple_cu_price,
            min_wo_chain_id_acceptable_gas_price=self._cfg.min_wo_chain_id_gas_price,
            token_dict=token_dict,
            default_token=default_token,
        )

    async def _calc_token_gas_price(
        self,
        token: TokenModel,
        base_price_usd: float,
        price_acct: _PythPriceAcct | None,
    ) -> MpTokenGasPriceModel | None:
        is_const_price = False
        suggested_price = 0
        min_price = 0
        token_price_usd = price_acct.aggregate_price_info.price if price_acct else 0.0

        if self._cfg.const_gas_price is not None:
            is_const_price = True
            suggested_price = self._cfg.const_gas_price
            min_price = self._cfg.const_gas_price
        elif self._cfg.min_gas_price:
            if not self._cfg.pyth_url_list:
                is_const_price = True
                suggested_price = self._cfg.min_gas_price
                min_price = self._cfg.min_gas_price

        if not is_const_price:
            if (token_price_usd <= 0.0) or (base_price_usd <= 0.0):
                return None

            # SOL token has 9 fractional digits
            # NATIVE token has 18 fractional digits
            net_price = int((base_price_usd * (10**9)) / token_price_usd)
            suggested_price = int(net_price * (1 + self._cfg.operator_fee))
            min_price = net_price

        # Populate data regardless if const_gas_price or not.
        gas_price_deque = self._recent_gas_price_dict.setdefault(token.chain_id, deque())
        recent_slot: int = await self._sol_client.get_recent_slot()
        gas_price_deque.append(MpSlotGasPriceModel(slot=recent_slot, gas_price=suggested_price, min_gas_price=min_price))
        if len(gas_price_deque) > self._recent_gas_price_cnt:
            gas_price_deque.popleft()

        min_price = min(gas_price_deque, key=lambda x: x.min_gas_price).min_gas_price

        return MpTokenGasPriceModel(
            chain_id=token.chain_id,
            token_name=token.name,
            token_mint=token.mint,
            token_price_usd=int(token_price_usd * self._token_usd_precision),
            is_default_token=token.is_default,
            suggested_gas_price=suggested_price,
            is_const_gas_price=is_const_price,
            min_acceptable_gas_price=self._cfg.min_gas_price or 0,
            min_executable_gas_price=min_price,
            gas_price_list=list(gas_price_deque),
        )

    async def _open_pyth_connect(self) -> bool:
        if not self._cfg.pyth_url_list:
            return True

        pyth_url_idx = 0
        product_list: list[_PythProdAcct] = list()
        while not product_list:
            if pyth_url_idx >= min(len(self._cfg.pyth_url_list), len(self._cfg.pyth_ws_url_list)):
                _LOG.error("no available Pyth urls, disable gas-price calculations")
                break

            pyth_url = self._cfg.pyth_url_list[pyth_url_idx]
            pyth_ws_url = self._cfg.pyth_ws_url_list[pyth_url_idx]
            pyth_url_idx += 1
            _LOG.info("Try Pyth URL %s, WS URL %s", pyth_url, pyth_ws_url, extra=self._msg_filter)

            try:
                for network in ("pythnet", "mainnet", "devnet", "testnet"):
                    mapping_acct = _pyth_utils.get_key(network, "mapping")
                    program_key = _pyth_utils.get_key(network, "program")

                    pyth_client = _PythClient(
                        solana_endpoint=pyth_url,
                        solana_ws_endpoint=pyth_ws_url,
                        first_mapping_account_key=mapping_acct,
                        program_key=program_key,
                        aiohttp_client_session=self._sol_client.session,  # use the same session with solana client
                    )
                    if product_list := await pyth_client.get_products():
                        self._pyth_client = pyth_client
                        self._product_list = product_list

                        self._watch_session = self._pyth_client.create_watch_session()
                        await self._watch_session.connect()

                        return True
                else:
                    continue

            except BaseException as exc:
                _LOG.warning("error on connect to pyth network", exc_info=exc, extra=self._msg_filter)
                continue

        return False

    async def _update_token_dict(self) -> None:
        _LOG.info("start update token list")
        price_acct_dict: dict[str, _PythPriceAcct] = dict()
        for product in self._product_list:
            token = product.attrs.get("base", None)
            currency = product.attrs.get("quote_currency", None)
            asset_type = product.attrs.get("asset_type", None)
            if token and (currency, asset_type) == ("USD", "Crypto"):
                price_list = await product.get_prices()
                for price in price_list.values():
                    if price.price_type == _PythPriceType.PRICE:
                        price_acct_dict[token] = price

        self._price_acct_full_dict = price_acct_dict
        _LOG.info("token list is updated")

    async def _update_pyth_acct_loop(self) -> None:
        stop_task = asyncio.create_task(self._stop_event.wait())
        while not self._stop_event.is_set():
            try:
                if not self._pyth_client:
                    with logging_context(ctx="mp-gas-price-connect"):
                        await self._open_pyth_connect()

                if self._pyth_client:
                    with logging_context(ctx="mp-gas-price-update-token-list"):
                        if not self._price_acct_full_dict:
                            await self._update_token_dict()
                        if not self._base_price_acct:
                            self._base_price_acct = await self._get_price_account(CHAIN_TOKEN_NAME)
                        if not self._base_price_acct:
                            continue

                if self._watch_session:
                    update_task = asyncio.create_task(self._watch_session.next_update())
                    await asyncio.wait({update_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
                else:
                    await asyncio.wait({stop_task}, timeout=1.0)
            except BaseException as exc:
                _LOG.error("error on update gas-price accounts", exc_info=exc, extra=self._msg_filter)

    async def _get_price_account(self, token: str) -> _PythPriceAcct | None:
        if (not self._watch_session) or (not self._price_acct_full_dict):
            return None

        if not (price_acct := self._price_acct_dict.get(token, None)):
            if price_acct := self._price_acct_full_dict.get(token, None):
                self._price_acct_dict[token] = price_acct
                await self._watch_session.subscribe(price_acct)
            elif token not in self._price_acct_failed_set:
                self._price_acct_failed_set.add(token)
                _LOG.error(log_msg("Pyth doesn't have information about the token: {Token}", Token=token))

        return price_acct

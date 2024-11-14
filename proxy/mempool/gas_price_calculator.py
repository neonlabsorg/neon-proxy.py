from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from typing import Final

from common.config.constants import ONE_BLOCK_SEC, DEFAULT_TOKEN_NAME, CHAIN_TOKEN_NAME
from common.cu_price.api import PriorityFeeCfg
from common.cu_price.pyth_price_account import PythPriceAccount
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel, TokenModel
from common.solana.cb_program import SolCbProg
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana_rpc.ws_client import SolWatchAccountSession
from common.utils.json_logger import log_msg, logging_context
from .server_abc import MempoolComponent, MempoolServerAbc
from ..base.mp_api import MpGasPriceModel, MpSlotGasPriceModel, MpTokenGasPriceModel

_LOG = logging.getLogger(__name__)


class MpGasPriceCalculator(MempoolComponent):
    _token_usd_precision: Final[int] = 100_000
    _fee_precision: Final[int] = 100_000
    _update_sec: Final[int] = int(16 * ONE_BLOCK_SEC)

    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)

        self._watch_session = SolWatchAccountSession(self._cfg, self._sol_client, commit=SolCommit.Confirmed)

        self._stop_event = asyncio.Event()
        self._update_pyth_acct_task: asyncio.Task | None = None
        self._update_gas_price_task: asyncio.Task | None = None

        self._price_acct_dict: dict[str, PythPriceAccount] = dict(
            SOL=PythPriceAccount.new_empty("SOL", SolPubKey.from_raw("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")),
            NEON=PythPriceAccount.new_empty("NEON", SolPubKey.from_raw("F2VfCymdNQiCa8Vyg5E7BwEv9UPwfm8cVN6eqQLqXiGo")),
            ETH=PythPriceAccount.new_empty("ETH", SolPubKey.from_raw("42amVS4KgzR9rA28tkVYqVXjq9Qa8dcZQMbH5EYFX6XC")),
            USDC=PythPriceAccount.new_empty("USDC", SolPubKey.from_raw("Dpw1EAVrSB1ibxiDQyTAW6Zip3J4Btk2x4SgApQCeFbX")),
            USDT=PythPriceAccount.new_empty("USDT", SolPubKey.from_raw("HT2PLQBcG5EiCcNSaMHAjSgd9F98ecpATbk4Sk5oYuM")),
        )

        self._gas_price = MpGasPriceModel(
            chain_token_price_usd=0,
            operator_fee=int(self._cfg.operator_fee * self._fee_precision),
            priority_fee=int(self._cfg.priority_fee * self._fee_precision),
            cu_price=self._cfg.def_cu_price,
            simple_cu_price=self._cfg.def_simple_cu_price,
            min_wo_chain_id_acceptable_gas_price=self._cfg.min_wo_chain_id_gas_price,
            default_token=MpTokenGasPriceModel(
                chain_id=0,
                token_name=DEFAULT_TOKEN_NAME,
                token_mint=SolPubKey.default(),
                token_price_usd=0,
                is_default_token=True,
                is_const_gas_price=True,
                suggested_gas_price=0,
                profitable_gas_price=0,
                pct_gas_price=1,
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
        await self._watch_session.connect()
        self._update_pyth_acct_task = asyncio.create_task(self._update_pyth_acct_loop())
        self._update_gas_price_task = asyncio.create_task(self._update_gas_price_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._update_pyth_acct_task:
            await self._update_pyth_acct_task
        if self._update_gas_price_task:
            await self._update_gas_price_task

        if self._watch_session:
            await self._watch_session.disconnect()

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
                    fee_cfg = await self._cu_price_client.get_fee_cfg()
                    if gas_price := await self._get_gas_price(evm_cfg, fee_cfg):
                        self._gas_price = gas_price
                except BaseException as exc:
                    _LOG.error("error on update gas-price", exc_info=exc)

    async def _get_gas_price(self, evm_cfg: EvmConfigModel, fee_cfg: PriorityFeeCfg) -> MpGasPriceModel | None:
        base_price_acct = await self._get_price_account(CHAIN_TOKEN_NAME)
        base_price_usd = base_price_acct.price

        token_dict: dict[str, MpTokenGasPriceModel] = dict()
        default_token: MpTokenGasPriceModel | None = None

        for token in evm_cfg.token_dict.values():
            price_acct = await self._get_price_account(token.name)
            token_gas_price = await self._calc_token_gas_price(fee_cfg, token, base_price_usd, price_acct)
            if token_gas_price:
                token_dict[token.name] = token_gas_price
                if token_gas_price.is_default_token:
                    default_token = token_gas_price
            else:
                return None

        assert default_token is not None, "DEFAULT TOKEN NOT FOUND!"

        # Logic is simple:
        #   - User pays for gas-usage
        #   - Each gas-unit for gas-price
        #   - Gas-price = Base-Gas-Price + (Operator-Fee * Base-Gas-Price) + (Priority-Fee * Base-GasPrice)
        #   --- Base-Gas-Price -> covers SOLs
        #   --- Base-Gas-Price * Operator-Fee -> brings profit to the Operator
        #   --- Base-Gas-Price * Priority-Fee -> coverts SOLs for Solana Priority Fee (CUs price)
        #   - It means, that Gas-Usage * Base-Gas-Price * Priority-Fee - is the cost of Solana Priority Fee in NEONs
        #   - It means, that Gas-Usage * Priority-Fee - is the cost of Solana Priority Fee in SOLs
        cu_price = int(fee_cfg.priority_fee * NeonProg.BaseGas * SolCbProg.MicroLamport / SolCbProg.MaxCuLimit)

        return MpGasPriceModel(
            chain_token_price_usd=int(base_price_usd * self._token_usd_precision),
            operator_fee=int(fee_cfg.operator_fee * self._fee_precision),
            priority_fee=int(fee_cfg.priority_fee * self._fee_precision),
            cu_price=cu_price,
            simple_cu_price=fee_cfg.def_simple_cu_price,
            min_wo_chain_id_acceptable_gas_price=self._cfg.min_wo_chain_id_gas_price,
            token_dict=token_dict,
            default_token=default_token,
        )

    async def _calc_token_gas_price(
        self,
        fee_cfg: PriorityFeeCfg,
        token: TokenModel,
        base_price_usd: float,
        price_acct: PythPriceAccount,
    ) -> MpTokenGasPriceModel | None:
        is_const_price = False
        net_price = 0
        token_price_usd = price_acct.price

        if fee_cfg.const_gas_price is not None:
            is_const_price = True
            net_price = fee_cfg.const_gas_price
        elif fee_cfg.min_gas_price:
            if not self._cfg.pyth_url_list:
                is_const_price = True
                net_price = fee_cfg.min_gas_price

        if not is_const_price:
            if (token_price_usd <= 0.0) or (base_price_usd <= 0.0):
                return None

            # SOL token has 9 fractional digits
            # NATIVE token has 18 fractional digits
            net_price = int((base_price_usd * (10**9)) / token_price_usd)

        # Populate data regardless if const_gas_price or not.
        profitable_price = int(net_price * (1 + fee_cfg.operator_fee))
        suggested_price = int(net_price * (1 + fee_cfg.priority_fee + fee_cfg.operator_fee))

        gas_price_deque = self._recent_gas_price_dict.setdefault(token.chain_id, deque())
        recent_slot: int = await self._sol_client.get_recent_slot()
        gas_price_deque.append(
            MpSlotGasPriceModel(slot=recent_slot, gas_price=profitable_price)
        )
        if len(gas_price_deque) > self._recent_gas_price_cnt:
            gas_price_deque.popleft()
        min_price = min(gas_price_deque, key=lambda x: x.gas_price).gas_price

        return MpTokenGasPriceModel(
            chain_id=token.chain_id,
            token_name=token.name,
            token_mint=token.mint,
            token_price_usd=int(token_price_usd * self._token_usd_precision),
            is_default_token=token.is_default,
            is_const_gas_price=is_const_price,
            suggested_gas_price=suggested_price,
            profitable_gas_price=profitable_price,
            pct_gas_price=max(net_price // 100, 1),
            min_acceptable_gas_price=fee_cfg.min_gas_price or 0,
            min_executable_gas_price=min_price,
            gas_price_list=list(gas_price_deque),
        )

    async def _update_pyth_acct_loop(self) -> None:
        stop_task = asyncio.create_task(self._stop_event.wait())
        while not self._stop_event.is_set():
            try:
                if self._watch_session:
                    update_task = asyncio.create_task(self._watch_session.update())
                    await asyncio.wait({update_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
                else:
                    await asyncio.wait({stop_task}, timeout=1.0)
            except BaseException as exc:
                _LOG.error("error on update gas-price accounts", exc_info=exc, extra=self._msg_filter)

    async def _get_price_account(self, token: str) -> PythPriceAccount:
        if not self._watch_session:
            return PythPriceAccount.default()

        if not (price_acct := self._price_acct_dict.get(token, None)):
            _LOG.error(log_msg("Pyth doesn't have information about the token: {Token}", Token=token))
            return PythPriceAccount.default()

        elif not (raw_acct := self._watch_session.get_account(price_acct.address)):
            await self._watch_session.subscribe_account(price_acct.address)
            raw_acct = self._watch_session.get_account(price_acct.address)

        price_acct.update_data(raw_acct)
        return price_acct

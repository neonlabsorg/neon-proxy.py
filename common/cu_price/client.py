import asyncio
import contextlib
import dataclasses
import logging
import time
from collections import deque
from typing import Sequence, Final

from .api import CuPriceRequest, PriorityFeeCfg
from .atlas_fee_client import AtlasFeeClient
from .dynamic_cfg_client import DynamicFeeCfgClient
from .solana_fee_client import SolFeeClient
from ..config.config import Config, CuPriceMode
from ..config.constants import ONE_BLOCK_SEC
from ..solana.pubkey import SolPubKey
from ..utils.json_logger import logging_context

_LOG = logging.getLogger(__name__)

@dataclasses.dataclass(frozen=True)
class _Item:
    key: int
    time_sec: int
    cu_price: int

    @staticmethod
    def calc_key(account_key_list: Sequence[SolPubKey]) -> int:
        return hash(tuple(sorted(map(lambda x: hash(x), account_key_list))))


class CuPriceClient:
    _clear_time_sec: Final[int] = int(ONE_BLOCK_SEC * 32)

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._fee_cfg_client = DynamicFeeCfgClient(cfg)
        self._atlas_fee_client = AtlasFeeClient(cfg)
        self._sol_fee_client = SolFeeClient(cfg)

        self._cu_price_dict: dict[int, _Item] = dict()
        self._cu_price_queue: deque[_Item] = deque()

        self._stop_event = asyncio.Event()
        self._clear_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._clear_task = asyncio.create_task(self._clear_loop())

        await asyncio.gather(
            self._atlas_fee_client.start(),
            self._sol_fee_client.start(),
        )

    async def stop(self) -> None:
        self._stop_event.set()

        await asyncio.gather(
            self._atlas_fee_client.stop(),
            self._sol_fee_client.stop(),
        )
        if self._clear_task:
            await self._clear_task

    async def get_cu_price(self, account_key_list: Sequence[SolPubKey]) -> int:
        key = _Item.calc_key(account_key_list)
        if item := self._cu_price_dict.get(key, None):
            _LOG.debug("use cached %s CU-price", item.cu_price)
            return item.cu_price

        req = await self._get_cu_price_req(account_key_list)
        if req.cu_price_mode == CuPriceMode.Default:
            _LOG.debug("use default CU-price %s", req.def_cu_price)
            cu_price = req.def_cu_price
        elif req.cu_price_mode == CuPriceMode.Atlas:
            cu_price = await self._atlas_fee_client.get_cu_price(req)
        elif req.cu_price_mode == CuPriceMode.Solana:
            cu_price = await self._sol_fee_client.get_cu_price(req)
        else:
            cu_price = 0

        cu_price = max(cu_price, req.def_cu_price)
        now = int(time.monotonic())
        item = _Item(key=key, cu_price=cu_price, time_sec=now)
        self._cu_price_dict[key] = item
        self._cu_price_queue.append(item)

        return cu_price

    async def get_fee_cfg(self) -> PriorityFeeCfg:
        return await self._fee_cfg_client.get_cfg()

    async def _clear_loop(self) -> None:
        with logging_context(ctx="cu-price"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(self._stop_event.wait(), 1)
                if self._stop_event.is_set():
                    break

                try:
                    self._clear_cache()
                except BaseException as exc:
                    _LOG.error("error on clearing cu-price-cache", exc_info=exc)

    def _clear_cache(self) -> None:
        if not self._cu_price_queue:
            return

        clear_time_sec = int(time.monotonic()) - self._clear_time_sec
        while self._cu_price_queue and (self._cu_price_queue[0].time_sec < clear_time_sec):
            item = self._cu_price_queue.popleft()
            self._cu_price_dict.pop(item.key, None)

    async def _get_cu_price_req(self, account_key_list: Sequence[SolPubKey]) -> CuPriceRequest:
        cfg = await self.get_fee_cfg()

        return CuPriceRequest(
            cu_price_mode=cfg.cu_price_mode,
            cu_price_level=cfg.cu_price_level,
            def_cu_price=cfg.def_cu_price,
            account_key_list=account_key_list,
        )

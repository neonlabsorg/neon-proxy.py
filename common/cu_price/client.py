import logging
from typing import Sequence

from .api import CuPriceRequest
from .atlas_fee_client import AtlasFeeClient
from .solana_fee_client import SolFeeClient
from ..config.config import Config, CuPriceMode
from ..solana.pubkey import SolPubKey

_LOG = logging.getLogger(__name__)


class CuPriceClient:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._atlas_fee_client = AtlasFeeClient(cfg)
        self._sol_fee_client = SolFeeClient(cfg)

    async def start(self) -> None:
        await self._atlas_fee_client.start()
        await self._sol_fee_client.start()

    async def stop(self) -> None:
        await self._atlas_fee_client.stop()
        await self._sol_fee_client.stop()

    async def get_cu_price(self, account_key_list: Sequence[SolPubKey]) -> int:
        req = self._get_cu_price_req(account_key_list)

        if req.cu_price_mode == CuPriceMode.Default:
            _LOG.debug("use default CU-price %s", int(req.def_cu_price))
            return req.def_cu_price

        if req.cu_price_mode == CuPriceMode.Atlas:
            cu_price = await self._atlas_fee_client.get_cu_price(req)
        elif req.cu_price_mode == CuPriceMode.Solana:
            cu_price = await self._sol_fee_client.get_cu_price(req)
        else:
            cu_price = 0
        return max(cu_price, req.def_cu_price)

    def _get_cu_price_req(self, account_key_list: Sequence[SolPubKey]) -> CuPriceRequest:
        return CuPriceRequest(
            cu_price_mode=self._cfg.cu_price_mode,
            cu_price_level=self._cfg.cu_price_level,
            def_cu_price=self._cfg.def_cu_price,
            account_key_list=account_key_list,
        )


import logging

from .api import CuPriceRequest
from .solana_fee_api import SolPriorityFeeResp
from ..config.config import CuPriceLevel
from ..http.utils import HttpURL
from ..jsonrpc.client import JsonRpcClient
from ..solana.cb_program import SolCbProg
from ..solana.pubkey import SolPubKeyField

_LOG = logging.getLogger(__name__)


class SolFeeClient(JsonRpcClient):
    def __init__(self, *args, **kwargs) -> None:
        # solders doesn't have implementation for priority fee
        super().__init__(*args, **kwargs)

        url_list = tuple([HttpURL(url) for url in self._cfg.sol_url_list])
        self.connect(base_url_list=url_list)

        self._cu_level_dict: dict[CuPriceLevel, int] = {
            CuPriceLevel.Min: 10,
            CuPriceLevel.Low: 25,
            CuPriceLevel.Medium: 50,
            CuPriceLevel.High: 75,
            CuPriceLevel.VeryHigh: 95,
            CuPriceLevel.UnsafeMax: 100,
            CuPriceLevel.Default: 50,
            CuPriceLevel.Recommended: 50,
        }

    async def get_cu_price(self, req: CuPriceRequest) -> int:
        try:
            item_list = await self._estimate_fee(list(req.account_key_list))

            min_cu_price = min(map(lambda x: x.cu_price, item_list))
            max_cu_price = max(map(lambda x: x.cu_price, item_list))
            avg_cu_price = sum(map(lambda x: x.cu_price, item_list)) // len(item_list)

            pct = self._cu_level_dict.get(req.cu_price_level)
            min_pct = self._cu_level_dict.get(CuPriceLevel.Min)
            med_pct = 50
            max_pct = 100

            if pct == med_pct:
                cu_price = max(avg_cu_price, SolCbProg.BaseCuPrice)
            elif pct < med_pct:
                cu_price_diff = avg_cu_price - min_cu_price
                pct_diff = med_pct - min_pct
                cu_price = int(min_cu_price + pct * cu_price_diff / pct_diff)
            else:
                cu_price_diff = max_cu_price - avg_cu_price
                pct_diff = max_pct - med_pct
                cu_price = int(avg_cu_price + pct * cu_price_diff / pct_diff)

            _LOG.debug("got CU-price %d for %d accounts", int(cu_price), len(req.account_key_list))
            return int(cu_price)

        except BaseException as exc:
            _LOG.warning("fail to get priority fee", exc_info=exc, extra=self._msg_filter)

        return 0

    @JsonRpcClient.method(name="getRecentPrioritizationFees")
    async def _estimate_fee(self, account_key_list: list[SolPubKeyField]) -> list[SolPriorityFeeResp]: ...

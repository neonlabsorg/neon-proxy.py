import logging

from .api import CuPriceRequest
from .solana_fee_api import SolPriorityFeeResp
from ..http.utils import HttpURL
from ..jsonrpc.client import JsonRpcClient
from ..solana.pubkey import SolPubKeyField

_LOG = logging.getLogger(__name__)


class SolFeeClient(JsonRpcClient):
    def __init__(self, *args, **kwargs) -> None:
        # solders doesn't have implementation for priority fee
        super().__init__(*args, **kwargs)

        url_list = tuple([HttpURL(url) for url in self._cfg.sol_url_list])
        self.connect(base_url_list=url_list)

    async def get_cu_price(self, req: CuPriceRequest) -> int:
        try:
            resp = await self._estimate_fee(list(req.account_key_list))
            cu_price = sum(map(lambda x: x.cu_price, resp)) // len(resp)

            _LOG.debug("got CU-price %d for %d accounts", int(cu_price), len(req.account_key_list))
            return int(cu_price)

        except BaseException as exc:
            _LOG.warning("fail to get priority fee", exc_info=exc, extra=self._msg_filter)

        return 0

    @JsonRpcClient.method(name="getRecentPrioritizationFees")
    async def _estimate_fee(self, account_key_list: list[SolPubKeyField]) -> list[SolPriorityFeeResp]: ...

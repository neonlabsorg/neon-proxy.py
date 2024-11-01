import logging

from .api import CuPriceRequest
from .atlas_fee_api import AtlasFeeResp, AtlasFeeRequest, AtlasFeeCfg
from ..config.config import CuPriceLevel
from ..http.utils import HttpURL
from ..jsonrpc.client import JsonRpcClient

_LOG = logging.getLogger(__name__)


class AtlasFeeClient(JsonRpcClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if self._cfg.atlas_fee_url_list:
            url_list = tuple([HttpURL(url) for url in self._cfg.atlas_fee_url_list])
            self.connect(base_url_list=url_list)
            self._is_active = True
        else:
            self._is_active = False

    async def get_cu_price(self, req: CuPriceRequest) -> int:
        assert self._is_active
        try:
            if req.cu_price_level == CuPriceLevel.Recommended:
                fee_cfg = AtlasFeeCfg(recommended=True)
            else:
                fee_cfg = AtlasFeeCfg(level=req.cu_price_level, include_vote=False)

            atlas_req = AtlasFeeRequest(account_key_list=list(req.account_key_list), cfg=fee_cfg)
            resp = await self._estimate_fee(atlas_req)
            _LOG.debug("got CU-price %d for %d accounts", int(resp.fee), len(req.account_key_list))
            return int(resp.fee)

        except BaseException as exc:
            _LOG.warning("fail to get priority fee", exc_info=exc, extra=self._msg_filter)

        return 0

    @JsonRpcClient.method(name="getPriorityFeeEstimate")
    async def _estimate_fee(self, fee_request: AtlasFeeRequest) -> AtlasFeeResp: ...

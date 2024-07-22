import logging
from typing import Sequence

from .fee_api import FeeLevelValidator, FeeLevel, FeeResp, FeeRequest, FeeCfg
from ..http.utils import HttpURL
from ..jsonrpc.client import JsonRpcClient
from ..solana.pubkey import SolPubKey

_LOG = logging.getLogger(__name__)


class AtlasFeeClient(JsonRpcClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if self._cfg.atlas_fee_url_list:
            url_list = tuple([HttpURL(url) for url in self._cfg.atlas_fee_url_list])
            self.connect(base_url_list=url_list)
            self._is_active = True

            fee_level = FeeLevelValidator.from_raw(self._cfg.atlas_fee_level)
            if fee_level == FeeLevel.Unknown:
                fee_level = FeeLevel.Recommended
                _LOG.debug("use '%s' level", fee_level)

            if fee_level == FeeLevel.Recommended:
                self._fee_cfg = FeeCfg(recommended=True)
            else:
                self._fee_cfg = FeeCfg(level=fee_level, include_vote=False)

        else:
            self._is_active = False
            self._fee_cfg = FeeCfg()

    async def get_cu_price(self, account_key_list: Sequence[SolPubKey]) -> int:
        if not self._is_active:
            _LOG.debug("use default CU-price %s", int(self._cfg.cu_price))
            return self._cfg.cu_price

        try:
            req = FeeRequest(account_key_list=list(account_key_list), cfg=self._fee_cfg)
            resp = await self._estimate_fee(req)
            _LOG.debug("use CU-price %d for %d accounts", int(resp.fee), len(account_key_list))
            return int(resp.fee)

        except BaseException as exc:
            _LOG.warning("fail to get priority fee", exc_info=exc, extra=self._msg_filter)

        _LOG.debug("use default CU-price %s", int(self._cfg.cu_price))
        return self._cfg.cu_price

    @JsonRpcClient.method(name="getPriorityFeeEstimate")
    async def _estimate_fee(self, fee_request: FeeRequest) -> FeeResp: ...

import logging
from decimal import Decimal

from .api import PriorityFeeCfg
from .dynamic_cfg_api import PriorityFeeCfgResp
from ..http.utils import HttpURL
from ..jsonrpc.client import JsonRpcClient
from ..utils.cached import ttl_cached_method

_LOG = logging.getLogger(__name__)


class DynamicFeeCfgClient(JsonRpcClient):
    def __init__(self, *args, **kwargs) -> None:
        # solders doesn't have implementation for priority fee
        super().__init__(*args, **kwargs)

        if self._cfg.dynamic_fee_cfg_url_list:
            self._is_active = True
            url_list = tuple([HttpURL(url) for url in self._cfg.dynamic_fee_cfg_url_list])
            self.connect(base_url_list=url_list)
        else:
            self._is_active = False

        self._base_cfg = PriorityFeeCfg(
            operator_fee=self._cfg.operator_fee,
            const_gas_price=self._cfg.const_gas_price,
            min_gas_price=self._cfg.min_gas_price,
            cu_price_mode=self._cfg.cu_price_mode,
            cu_price_level=self._cfg.cu_price_level,
            def_cu_price=self._cfg.def_cu_price,
            def_simple_cu_price=self._cfg.def_simple_cu_price,
        )

    @ttl_cached_method(ttl_sec=60)
    async def get_cfg(self) -> PriorityFeeCfg:
        if not self._is_active:
            return self._base_cfg

        try:
            resp = await self._get_cfg()
            return PriorityFeeCfg(
                operator_fee=resp.operator_fee,
                const_gas_price=resp.const_gas_price * (10**9),
                min_gas_price=resp.min_gas_price * (10**9),
                cu_price_mode=resp.cu_price_mode,
                cu_price_level=resp.cu_price_level,
                def_cu_price=resp.def_cu_price,
                def_simple_cu_price=resp.def_simple_cu_price,
            )

        except BaseException as exc:
            _LOG.warning("fail to get priority fee config", exc_info=exc, extra=self._msg_filter)

        return self._base_cfg

    @JsonRpcClient.method(name="getPriorityFeeCfg")
    async def _get_cfg(self) -> PriorityFeeCfgResp: ...


from typing import ClassVar

from .server_abc import MempoolApi
from ..base.mp_api import MpGasPriceModel, MpRecentGasPricesModel, MpRequest


class MpGasPriceApi(MempoolApi):
    name: ClassVar[str] = "Mempool::GasPrice"

    @MempoolApi.method(name="getGasPrice")
    def get_gas_price(self) -> MpGasPriceModel:
        return self._server.get_gas_price()

    @MempoolApi.method(name="getRecentGasPricesList")
    def get_recent_gas_prices_list(self, req: MpRequest) -> MpRecentGasPricesModel:
        return self._server.get_recent_gas_prices_list(req.chain_id)

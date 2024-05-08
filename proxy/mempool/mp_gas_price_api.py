from typing import ClassVar

from .server_abc import MempoolApi
from ..base.mp_api import MpGasPriceModel


class MpGasPriceApi(MempoolApi):
    name: ClassVar[str] = "Mempool::GasPrice"

    @MempoolApi.method(name="getGasPrice")
    def get_gas_price(self) -> MpGasPriceModel:
        return self._server.get_gas_price()

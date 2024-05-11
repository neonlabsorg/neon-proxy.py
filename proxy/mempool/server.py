from __future__ import annotations

import asyncio

from .alt_loader import SolAltLoader
from .gas_price_calculator import MpGasPriceCalculator
from .mp_evm_config_api import MpEvmCfgApi
from .mp_gas_price_api import MpGasPriceApi
from .mp_transaction_api import MpTxApi
from .server_abc import MempoolServerAbc
from .transaction_executor import MpTxExecutor
from ..base.mp_api import MpGasPriceModel


class MempoolServer(MempoolServerAbc):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.set_process_cnt(1)
        self.set_worker_cnt(1)
        self.listen(host="127.0.0.1", port=self._cfg.mp_port)

        self._gas_price_calc = MpGasPriceCalculator(self)
        self._tx_executor = MpTxExecutor(self)
        self._sol_stuck_alt_loader = SolAltLoader(self)

        self._add_api(MpEvmCfgApi(self))
        self._add_api(MpGasPriceApi(self))
        self._add_api(MpTxApi(self))

    async def on_server_start(self) -> None:
        await super().on_server_start()
        await asyncio.gather(
            self._gas_price_calc.start(),
            self._tx_executor.start(),
            self._sol_stuck_alt_loader.start(),
        )

    async def on_server_stop(self) -> None:
        await asyncio.gather(
            self._gas_price_calc.stop(),
            self._tx_executor.stop(),
            self._sol_stuck_alt_loader.stop(),
            super().on_server_stop(),
        )

    def get_gas_price(self) -> MpGasPriceModel:
        return self._gas_price_calc.get_gas_price()

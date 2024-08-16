from typing import Sequence

from common.app_data.client import AppDataClient
from .ex_api import (
    EXECUTOR_ENDPOINT,
    ExecTxRequest,
    ExecStuckTxRequest,
    ExecTxResp,
    DestroyAltListRequest,
    DestroyAltListResp,
    NeonAltModel,
)
from .mp_api import MpTxModel, MpStuckTxModel, MpTokenGasPriceModel, MpGasPriceModel
from .op_api import OpResourceModel


class ExecutorClient(AppDataClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(host=self._cfg.exec_ip, port=self._cfg.exec_port, path=EXECUTOR_ENDPOINT)
        self.set_timeout_sec(60 * 90)  # 90 minutes

    async def exec_tx(self, tx: MpTxModel, resource: OpResourceModel, gas_price: MpGasPriceModel) -> ExecTxResp:
        return await self._exec_tx(ExecTxRequest(tx=tx, resource=resource, gas_price=gas_price))

    async def complete_stuck_tx(
        self,
        stuck_tx: MpStuckTxModel,
        resource: OpResourceModel,
        gas_price: MpGasPriceModel,
    ) -> ExecTxResp:
        return await self._complete_stuck_tx(
            ExecStuckTxRequest(
                stuck_tx=stuck_tx,
                resource=resource,
                gas_price=gas_price,
            )
        )

    async def destroy_alt_list(self, req_id: dict, stuck_alt_list: Sequence[NeonAltModel]) -> None:
        req = DestroyAltListRequest(req_id=req_id, alt_list=list(stuck_alt_list))
        await self._destroy_alt_list(req)

    @AppDataClient.method(name="executeNeonTransaction")
    async def _exec_tx(self, request: ExecTxRequest) -> ExecTxResp: ...

    @AppDataClient.method(name="completeStuckNeonTransaction")
    async def _complete_stuck_tx(self, request: ExecStuckTxRequest) -> ExecTxResp: ...

    @AppDataClient.method(name="destroyAltList")
    async def _destroy_alt_list(self, request: DestroyAltListRequest) -> DestroyAltListResp: ...

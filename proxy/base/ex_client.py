from common.app_data.client import AppDataClient
from .ex_api import EXECUTOR_ENDPOINT, ExecTxRequest, ExecStuckTxRequest, ExecTxResp
from .mp_api import MpTxModel, MpStuckTxModel
from .op_api import OpResourceModel


class ExecutorClient(AppDataClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(host="127.0.0.1", port=self._cfg.executor_port, path=EXECUTOR_ENDPOINT)

    async def exec_tx(self, tx: MpTxModel, resource: OpResourceModel) -> ExecTxResp:
        return await self._exec_tx(ExecTxRequest(tx=tx, resource=resource))

    async def exec_stuck_tx(self, stuck_tx: MpStuckTxModel, resource: OpResourceModel) -> ExecTxResp:
        return await self._exec_stuck_tx(ExecStuckTxRequest(stuck_tx=stuck_tx, resource=resource))

    @AppDataClient.method(name="executeTransaction")
    async def _exec_tx(self, request: ExecTxRequest) -> ExecTxResp: ...

    @AppDataClient.method(name="executeStuckTransaction")
    async def _exec_stuck_tx(self, request: ExecStuckTxRequest) -> ExecTxResp: ...

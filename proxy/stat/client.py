from __future__ import annotations

from common.app_data.client import AppDataClient
from common.config.config import Config
from common.stat.api import RpcCallData
from common.stat.client import BaseStatClient, RpcStatClient
from .api import STATISTIC_ENDPOINT, TxDoneData, TxFailData, TxPoolData


class StatClient(AppDataClient, BaseStatClient, RpcStatClient):
    def __init__(self, cfg: Config) -> None:
        AppDataClient.__init__(self, cfg)
        BaseStatClient.__init__(self, cfg)
        RpcStatClient.__init__(self)
        self.connect(host="127.0.0.1", port=cfg.stat_port, path=STATISTIC_ENDPOINT)

    async def start(self) -> None:
        await AppDataClient.start(self)
        await BaseStatClient.start(self)

    async def stop(self) -> None:
        await AppDataClient.stop(self)
        await BaseStatClient.stop(self)

    def commit_tx_done(self, data: TxDoneData) -> None:
        self._put_to_queue(self._commit_tx_done, data)

    def commit_tx_fail(self, data: TxFailData) -> None:
        self._put_to_queue(self._commit_tx_fail, data)

    def commit_tx_pool(self, data: TxPoolData) -> None:
        self._put_to_queue(self._commit_tx_pool, data)

    @AppDataClient.method(name="commitRpcCall")
    async def _commit_rpc_call(self, data: RpcCallData) -> None: ...

    @AppDataClient.method(name="commitTransactionDone")
    async def _commit_tx_done(self, data: TxDoneData) -> None: ...

    @AppDataClient.method(name="commitTransactionFail")
    async def _commit_tx_fail(self, data: TxFailData) -> None: ...

    @AppDataClient.method(name="commitPool")
    async def _commit_tx_pool(self, data: TxPoolData) -> None: ...

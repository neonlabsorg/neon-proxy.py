from __future__ import annotations

from common.app_data.client import AppDataClient
from common.config.config import Config
from common.stat.api import RpcCallData
from common.stat.client import BaseStatClient
from common.stat.client_rpc import RpcStatClient
from .api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat, STATISTIC_ENDPOINT


class StatClient(AppDataClient, BaseStatClient, RpcStatClient):
    def __init__(self, cfg: Config) -> None:
        AppDataClient.__init__(self, cfg)
        BaseStatClient.__init__(self, cfg)
        self.connect(host=cfg.stat_ip, port=cfg.stat_port, path=STATISTIC_ENDPOINT)

    async def start(self) -> None:
        await AppDataClient.start(self)
        await BaseStatClient.start(self)

    async def stop(self) -> None:
        await AppDataClient.stop(self)
        await BaseStatClient.stop(self)

    def commit_block_stat(self, data: NeonBlockStat) -> None:
        self._put_to_queue(self._commit_block_stat, data)

    def commit_reindex_block_stat(self, data: NeonReindexBlockStat) -> None:
        self._put_to_queue(self._commit_reindex_block_stat, data)

    def commit_done_reindex_stat(self, data: NeonDoneReindexStat) -> None:
        self._put_to_queue(self._commit_done_reindex_stat, data)

    def commit_rpc_call(self, data: RpcCallData) -> None:
        self._put_to_queue(self._commit_rpc_call, data)

    @AppDataClient.method(name="commitRpcCall")
    async def _commit_rpc_call(self, data: RpcCallData) -> None: ...

    @AppDataClient.method(name="commitBlock")
    async def _commit_block_stat(self, data: NeonBlockStat) -> None: ...

    @AppDataClient.method(name="commitReindexBlock")
    async def _commit_reindex_block_stat(self, data: NeonReindexBlockStat) -> None: ...

    @AppDataClient.method(name="commitReindexDone")
    async def _commit_done_reindex_stat(self, data: NeonDoneReindexStat) -> None: ...

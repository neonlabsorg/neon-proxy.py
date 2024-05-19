from __future__ import annotations

from common.app_data.client import AppDataClient
from common.config.config import Config
from common.stat.client import BaseStatClient
from .api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat, NeonTxStat, STATISTIC_ENDPOINT


class StatClient(AppDataClient, BaseStatClient):
    def __init__(self, cfg: Config) -> None:
        AppDataClient.__init__(self, cfg)
        BaseStatClient.__init__(self, cfg)
        self.connect(host="127.0.0.1", port=cfg.stat_port, path=STATISTIC_ENDPOINT)

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

    def commit_tx_stat(self, data: NeonTxStat) -> None:
        self._put_to_queue(self._commit_tx_stat, data)

    @AppDataClient.method(name="commitBlock")
    async def _commit_block_stat(self, data: NeonBlockStat) -> None: ...

    @AppDataClient.method(name="commitReindexBlock")
    async def _commit_reindex_block_stat(self, data: NeonReindexBlockStat) -> None: ...

    @AppDataClient.method(name="commitReindexDone")
    async def _commit_done_reindex_stat(self, data: NeonDoneReindexStat) -> None: ...

    @AppDataClient.method(name="commitTransaction")
    async def _commit_tx_stat(self, data: NeonTxStat) -> None: ...

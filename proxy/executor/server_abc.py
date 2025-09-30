from __future__ import annotations

import asyncio
from typing import Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.cu_price.client import CuPriceClient
from common.neon_rpc.api_client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from indexer.db.indexer_db_client import IndexerDbClient
from ..base.ex_api import EXECUTOR_ENDPOINT
from ..base.intl_server import BaseIntlProxyServer, BaseIntlProxyComponent
from ..base.mp_client import MempoolClient
from ..base.op_client import OpResourceClient
from ..stat.client import StatClient


class ExecutorComponent(BaseIntlProxyComponent):
    def __init__(self, server: ExecutorServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _op_client(self) -> OpResourceClient:
        return self._server._op_client  # noqa

    @cached_property
    def _mp_client(self) -> MempoolClient:
        return self._server._mp_client  # noqa

    @cached_property
    def _cu_price_client(self) -> CuPriceClient:
        return self._server._cu_price_client  # noqa

    @cached_property
    def _stat_client(self) -> StatClient:
        return self._server._stat_client  # noqa

    @cached_property
    def _db(self) -> IndexerDbClient:
        return self._server._db  # noqa


class ExecutorApi(ExecutorComponent, AppDataApi):
    def __init__(self, server: ExecutorServerAbc) -> None:
        AppDataApi.__init__(self)
        ExecutorComponent.__init__(self, server)


class ExecutorServerAbc(BaseIntlProxyServer):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        op_client: OpResourceClient,
        cu_price_client: CuPriceClient,
        stat_client: StatClient,
        db: IndexerDbClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client)
        self._mp_client = mp_client
        self._op_client = op_client
        self._cu_price_client = cu_price_client
        self._stat_client = stat_client
        self._db = db
        self._stop_event = asyncio.Event()

    def _add_api(self, api: ExecutorApi) -> Self:
        return self.add_api(api, endpoint=EXECUTOR_ENDPOINT)

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._mp_client.start(),
            self._op_client.start(),
            self._cu_price_client.start(),
            self._stat_client.start(),
            self._db.start(),
        )
        await self._init_neon_prog()

    async def _on_server_stop(self) -> None:
        self._stop_event.set()
        await asyncio.gather(
            super()._on_server_stop(),
            self._mp_client.stop(),
            self._op_client.stop(),
            self._cu_price_client.stop(),
            self._stat_client.stop(),
            self._db.stop(),
        )

    async def _update_neon_prog(self) -> None:
        stop_task = asyncio.create_task(self._stop_event.wait())
        while not self._stop_event.is_set():
            await self._init_neon_prog()
            await asyncio.wait({stop_task}, timeout=1.0)

    async def _init_neon_prog(self) -> None:
        await self._mp_client.init_neon_prog()

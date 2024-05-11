from __future__ import annotations

import asyncio
from multiprocessing import Process

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property


class BaseProxyComponent:
    def __init__(self, server: BaseProxyServer):
        self._server = server

    @cached_property
    def _cfg(self) -> Config:
        return self._server._cfg  # noqa

    @cached_property
    def _core_api_client(self) -> CoreApiClient:
        return self._server._core_api_client  # noqa

    @cached_property
    def _sol_client(self) -> SolClient:
        return self._server._sol_client  # noqa

    @cached_property
    def _msg_filter(self) -> LogMsgFilter:
        return self._server._msg_filter  # noqa


class BaseProxyApi(BaseProxyComponent, AppDataApi):
    def __init__(self, server: BaseProxyServer) -> None:
        AppDataApi.__init__(self)
        BaseProxyComponent.__init__(self, server)


class BaseProxyServer(AppDataServer):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
    ):
        super().__init__(cfg)

        self._core_api_client = core_api_client
        self._sol_client = sol_client

    def start(self) -> None:
        # HttpServer has a pool of Processes, and they are stopped in the HttpServer.stop(),
        #   this process is stopped too as a result of HttpServer.stop()
        process = Process(target=super().start)
        process.start()

    async def on_server_start(self) -> None:
        await asyncio.gather(
            super().on_server_start(),
            self._sol_client.start(),
            self._core_api_client.start(),
        )

    async def on_server_stop(self) -> None:
        await asyncio.gather(
            super().on_server_stop(),
            self._core_api_client.stop(),
            self._sol_client.stop(),
        )

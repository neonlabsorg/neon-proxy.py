from __future__ import annotations

import asyncio

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from common.utils.process_pool import ProcessPool


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
    class _ProcessPool(ProcessPool):
        def __init__(self, server: BaseProxyServer) -> None:
            super().__init__()
            self._server: BaseProxyServer | None = server

        def _on_process_start(self, idx: int) -> None:
            self._server._on_process_start()

        async def _on_process_stop(self) -> None:
            self._server._on_process_stop()
            self._server = None

    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
    ):
        super().__init__(cfg)

        self._core_api_client = core_api_client
        self._sol_client = sol_client

        self._process_pool = self._ProcessPool(self)

    def start(self) -> None:
        self._register_handler_list()
        self._process_pool.start()

    def stop(self) -> None:
        self._process_pool.stop()

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._sol_client.start(),
            self._core_api_client.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            super()._on_server_stop(),
            self._core_api_client.stop(),
            self._sol_client.stop(),
        )

    def _on_process_start(self) -> None:
        super().start()

    def _on_process_stop(self) -> None:
        super().stop()

from __future__ import annotations

from typing_extensions import Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import ttl_cached_method, cached_property
from ..base.ex_api import EXECUTOR_ENDPOINT
from ..base.mp_client import MempoolClient
from ..base.op_client import OpResourceClient
from ..base.server import BaseProxyServer, BaseProxyComponent


class ExecutorComponent(BaseProxyComponent):
    def __init__(self, server: ExecutorServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _op_client(self) -> OpResourceClient:
        return self._server._op_client  # noqa

    async def get_evm_cfg(self) -> EvmConfigModel:
        return self._server.get_evm_cfg()


class ExecutorApi(ExecutorComponent, AppDataApi):
    def __init__(self, server: ExecutorServerAbc) -> None:
        AppDataApi.__init__(self)
        ExecutorComponent.__init__(self, server)


class ExecutorServerAbc(BaseProxyServer):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        op_client: OpResourceClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client)
        self._mp_client = mp_client
        self._op_client = op_client

    def _add_api(self, api: ExecutorApi) -> Self:
        return self.add_api(api, endpoint=EXECUTOR_ENDPOINT)

    @ttl_cached_method(ttl_sec=1)
    async def get_evm_cfg(self) -> EvmConfigModel:
        return await self._mp_client.get_evm_cfg()

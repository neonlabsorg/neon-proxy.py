from __future__ import annotations

import abc

from typing_extensions import Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana.signer import SolSigner
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from ..base.mp_client import MempoolClient
from ..base.op_api import OP_RESOURCE_ENDPOINT
from ..base.intl_server import BaseIntlProxyServer, BaseIntlProxyComponent
from ..stat.client import StatClient


class OpResourceComponent(BaseIntlProxyComponent):
    def __init__(self, server: OpResourceServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _stat_client(self) -> StatClient:
        return self._server._stat_client  # noqa


class OpResourceApi(OpResourceComponent, AppDataApi):
    def __init__(self, server: OpResourceServerAbc) -> None:
        AppDataApi.__init__(self)
        OpResourceComponent.__init__(self, server)


class OpResourceServerAbc(BaseIntlProxyServer, abc.ABC):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        stat_client: StatClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client)
        self._mp_client = mp_client
        self._stat_client = stat_client

    @abc.abstractmethod
    async def get_signer_list(self) -> tuple[SolSigner, ...]: ...

    async def get_evm_cfg(self) -> EvmConfigModel:
        evm_cfg = await self._mp_client.get_evm_cfg()
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.version)
        return evm_cfg

    def _add_api(self, api: OpResourceApi) -> Self:
        return self.add_api(api, endpoint=OP_RESOURCE_ENDPOINT)

    async def _on_server_start(self) -> None:
        await super()._on_server_start()
        await self._stat_client.start()

    async def _on_server_stop(self) -> None:
        await super()._on_server_stop()
        await self._stat_client.stop()

from __future__ import annotations

import abc
from typing import Sequence, Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.neon_rpc.client import CoreApiClient
from common.solana.signer import SolSigner
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from ..base.intl_server import BaseIntlProxyServer, BaseIntlProxyComponent
from ..base.mp_client import MempoolClient
from ..base.op_api import OP_RESOURCE_ENDPOINT
from ..stat.client import StatClient


class OpResourceComponent(BaseIntlProxyComponent):
    def __init__(self, server: OpResourceServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _stat_client(self) -> StatClient:
        return self._server._stat_client  # noqa

    @cached_property
    def _mp_client(self) -> MempoolClient:
        return self._server._mp_client  # noqa


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
    async def get_signer_list(self) -> Sequence[SolSigner]: ...

    def _add_api(self, api: OpResourceApi) -> Self:
        return self.add_api(api, endpoint=OP_RESOURCE_ENDPOINT)

    async def _on_server_start(self) -> None:
        await super()._on_server_start()
        await self._stat_client.start()

    async def _on_server_stop(self) -> None:
        await super()._on_server_stop()
        await self._stat_client.stop()

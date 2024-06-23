from __future__ import annotations

import abc
import asyncio

from typing_extensions import Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property, ttl_cached_method
from indexer.db.indexer_db_client import IndexerDbClient
from ..base.ex_client import ExecutorClient
from ..base.mp_api import MpGasPriceModel, MP_ENDPOINT
from ..base.op_client import OpResourceClient
from ..base.intl_server import BaseIntlProxyServer, BaseIntlProxyComponent
from ..stat.client import StatClient


class MempoolComponent(BaseIntlProxyComponent):
    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _db(self) -> IndexerDbClient:
        return self._server._db  # noqa

    @cached_property
    def _exec_client(self) -> ExecutorClient:
        return self._server._exec_client  # noqa

    @cached_property
    def _op_client(self) -> OpResourceClient:
        return self._server._op_client  # noqa

    @cached_property
    def _stat_client(self) -> StatClient:
        return self._server._stat_client  # noqa


class MempoolApi(MempoolComponent, AppDataApi):
    def __init__(self, server: MempoolServerAbc) -> None:
        AppDataApi.__init__(self)
        MempoolComponent.__init__(self, server)


class MempoolServerAbc(BaseIntlProxyServer, abc.ABC):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        exec_client: ExecutorClient,
        op_client: OpResourceClient,
        stat_client: StatClient,
        db: IndexerDbClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client)
        self._exec_client = exec_client
        self._op_client = op_client
        self._stat_client = stat_client
        self._db = db

    @ttl_cached_method(ttl_sec=1)
    async def get_evm_cfg(self) -> EvmConfigModel:
        # Finally, this method can be called from 2 places:
        #     - From Mempool Server when the EVM configuration is requested
        #     - From RPC Workers on requests from users or for internal logic in the RPC Worker
        #
        # The main point why it so is:
        #     - RPC worker caches the config for 1 second, so each RPC worker requests EVM config maximum 1 time per sec
        #     - Mempool caches the config for 1 second, so when the cache time on RPC worker is end,
        #       the request goes to Mempool, but only 1 of the requests goes to Solana
        #       (see logic in ttl_cached_method)
        #
        # As a result!, only Mempool requests EVM config from Solana and do it maximum 1 time per second,
        # and the period of requests doesn't depend on the number of clients(RPC worker/Mempool executor)
        # who needs the EVM config.
        return await self._core_api_client.get_evm_cfg()

    @abc.abstractmethod
    def get_gas_price(self) -> MpGasPriceModel: ...

    def _add_api(self, api: MempoolApi) -> Self:
        return self.add_api(api, endpoint=MP_ENDPOINT)

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._db.start(),
            self._op_client.start(),
            self._exec_client.start(),
            self._stat_client.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            super()._on_server_stop(),
            self._db.stop(),
            self._exec_client.stop(),
            self._op_client.stop(),
            self._stat_client.stop(),
        )

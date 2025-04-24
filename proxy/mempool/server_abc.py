from __future__ import annotations

import abc
import asyncio
from typing import Self

from common.app_data.server import AppDataApi
from common.config.config import Config
from common.cu_price.client import CuPriceClient
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from indexer.db.indexer_db_client import IndexerDbClient
from ..base.ex_client import ExecutorClient
from ..base.intl_server import BaseIntlProxyServer, BaseIntlProxyComponent
from ..base.mp_api import MpGasPriceModel, MP_ENDPOINT
from ..base.op_client import OpResourceClient
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

    @cached_property
    def _cu_price_client(self) -> CuPriceClient:
        return self._server._cu_price_client  # noqa

    @property
    def _gas_price(self) -> MpGasPriceModel:
        return self._server.get_gas_price()


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
        cu_price_client: CuPriceClient,
        stat_client: StatClient,
        db: IndexerDbClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client)
        self._exec_client = exec_client
        self._op_client = op_client
        self._cu_price_client = cu_price_client
        self._stat_client = stat_client
        self._db = db

    @abc.abstractmethod
    def get_gas_price(self) -> MpGasPriceModel: ...

    @abc.abstractmethod
    def get_evm_cfg(self) -> EvmConfigModel: ...

    def _add_api(self, api: MempoolApi) -> Self:
        return self.add_api(api, endpoint=MP_ENDPOINT)

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._db.start(),
            self._op_client.start(),
            self._cu_price_client.start(),
            self._exec_client.start(),
            self._stat_client.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            super()._on_server_stop(),
            self._db.stop(),
            self._exec_client.stop(),
            self._cu_price_client.stop(),
            self._op_client.stop(),
            self._stat_client.stop(),
        )

from __future__ import annotations

import abc
import logging

from common.config.config import Config
from common.ethereum.hash import EthAddress
from common.http.utils import HttpRequestCtx
from common.jsonrpc.server import JsonRpcApi
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from indexer.db.indexer_db_client import IndexerDbClient
from ..base.mp_client import MempoolClient
from ..base.op_client import OpResourceClient
from ..base.rpc_server_abc import BaseRpcServerComponent, BaseRpcServerAbc
from ..stat.client import StatClient

_LOG = logging.getLogger(__name__)


class PrivateRpcComponent(BaseRpcServerComponent):
    def __init__(self, server: PrivateRpcServerAbc) -> None:
        super().__init__(server)
        self._server = server

    @cached_property
    def _op_client(self) -> OpResourceClient:
        return self._server._op_client  # noqa


class PrivateRpcApi(PrivateRpcComponent, JsonRpcApi):
    def __init__(self, server: PrivateRpcServerAbc) -> None:
        JsonRpcApi.__init__(self)
        PrivateRpcComponent.__init__(self, server)


class PrivateRpcServerAbc(BaseRpcServerAbc, abc.ABC):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        stat_client: StatClient,
        op_client: OpResourceClient,
        db: IndexerDbClient,
    ) -> None:
        super().__init__(cfg, core_api_client, sol_client, mp_client, stat_client, db)
        self._op_client = op_client

    async def has_fee_less_tx_permit(
        self,
        ctx: HttpRequestCtx,
        sender: EthAddress,
        contract: EthAddress,
        tx_nonce: int,
        tx_gas_limit: int,
    ) -> bool:
        return True

    async def _on_server_start(self) -> None:
        try:
            await super()._on_server_start()
        except BaseException as exc:
            _LOG.error("error on start private RPC", exc_info=exc, extra=self._msg_filter)

    async def _on_server_stop(self) -> None:
        try:
            await super()._on_server_stop()
        except BaseException as exc:
            _LOG.error("error on stop private RPC", exc_info=exc, extra=self._msg_filter)

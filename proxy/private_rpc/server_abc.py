from __future__ import annotations

import asyncio
import logging
from typing import ClassVar

from common.config.config import Config
from common.jsonrpc.server import JsonRpcApi
from common.neon_rpc.client import CoreApiClient
from common.utils.cached import cached_property
from ..base.mp_client import MempoolClient
from ..base.op_client import OpResourceClient
from ..base.rpc_server import RpcServer
from ..stat.client import StatClient

_ENDPOINT_LIST = ["/api/v1/private_rpc/", "/api/v1/private_rpc/:token"]
_LOG = logging.getLogger(__name__)


class PrivateRpcComponent:
    def __init__(self, server: PrivateRpcServerAbc) -> None:
        self._server = server

    @cached_property
    def _core_api_client(self) -> CoreApiClient:
        return self._server._core_api_client

    @cached_property
    def _mp_client(self) -> MempoolClient:
        return self._server._mp_client  # noqa

    @cached_property
    def _op_client(self) -> OpResourceClient:
        return self._server._op_client  # noqa

    async def _get_default_chain_id(self) -> int:
        evm_cfg = await self._server.get_evm_cfg()
        return evm_cfg.default_chain_id


class PrivateRpcApi(PrivateRpcComponent, JsonRpcApi):
    def __init__(self, server: PrivateRpcServerAbc) -> None:
        JsonRpcApi.__init__(self)
        PrivateRpcComponent.__init__(self, server)


class PrivateRpcServerAbc(RpcServer):
    _stat_name: ClassVar[str] = "PrivateRpc"

    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        mp_client: MempoolClient,
        stat_client: StatClient,
        op_client: OpResourceClient,
    ) -> None:
        super().__init__(cfg, mp_client, stat_client)
        self._core_api_client = core_api_client
        self._op_client = op_client

    @classmethod
    def endpoint_list(cls) -> list[str]:
        return _ENDPOINT_LIST

    async def _on_server_start(self) -> None:
        try:
            await asyncio.gather(
                self._mp_client.start(),
                self._op_client.start(),
                self._stat_client.start(),
            )
        except BaseException as exc:
            _LOG.error("error on start private RPC", exc_info=exc, extra=self._msg_filter)

    async def _on_server_stop(self) -> None:
        try:
            await asyncio.gather(
                self._stat_client.stop(),
                self._op_client.stop(),
                self._mp_client.stop(),
            )
        except BaseException as exc:
            _LOG.error("error on stop private RPC", exc_info=exc, extra=self._msg_filter)

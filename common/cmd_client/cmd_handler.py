from __future__ import annotations

import asyncio
import logging
import uuid
from typing import ClassVar, Callable

from typing_extensions import Self

from ..config.config import Config
from ..neon_rpc.client import CoreApiClient
from ..solana_rpc.client import SolClient
from ..stat.api import RpcCallData
from ..stat.client_rpc import RpcStatClient
from ..utils.cached import cached_method

_LOG = logging.getLogger(__name__)


class BaseCmdHandler:
    command: ClassVar[str | None] = None

    def __init__(self, cfg: Config) -> None:
        self._subcmd_dict: dict[str, Callable] = dict()
        self._cfg = cfg
        self._stop_task_list: list[Callable] = list()
        self._client_dict: dict[str, object] = dict()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        return cls(cfg)

    async def execute(self, arg_space) -> int:
        try:
            if not self._subcmd_dict:
                subcmd_handler = self._exec_impl
            elif not (subcmd_handler := self._subcmd_dict.get(arg_space.subcommand, None)):
                _LOG.error("unknown command %s %s", self.command, arg_space)
                return 1
            return await subcmd_handler(arg_space)
        finally:
            await asyncio.gather(*[task() for task in self._stop_task_list])

    async def _exec_impl(self, arg_space) -> int:
        assert False, "no implementation"
        return 0  # noqa

    @staticmethod
    def _gen_req_id() -> dict:
        req_id = dict(uuid=str(uuid.uuid4()))
        _LOG.info("new req_id: %s", req_id)
        return req_id

    @cached_method
    def _get_rpc_stat_client(self) -> _FakeRpcStatClient:
        return _FakeRpcStatClient()

    @cached_method
    async def _get_sol_client(self) -> SolClient:
        return await self._new_client(SolClient, self._cfg, self._get_rpc_stat_client())

    @cached_method
    async def _get_core_api_client(self) -> CoreApiClient:
        stat_client = self._get_rpc_stat_client()
        sol_client = await self._get_sol_client()
        return await self._new_client(CoreApiClient, self._cfg, sol_client, stat_client)

    async def _new_client(self, client_type: type, *args):
        if client := self._client_dict.get(client_type.__name__, None):
            return client

        client = client_type(*args)
        if hasattr(client, "set_timeout_sec"):
            client.set_timeout_sec(300)

        async def _stop():
            await client.stop()

        self._stop_task_list.append(_stop)
        self._client_dict[client_type.__name__] = client

        await client.start()
        return client


class _FakeRpcStatClient(RpcStatClient):
    def commit_rpc_call(self, data: RpcCallData) -> None:
        pass

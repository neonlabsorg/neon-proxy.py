from __future__ import annotations

import asyncio
import time
from typing import ClassVar, Callable

from typing_extensions import Self

from common.config.config import Config
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_method
from proxy.base.mp_client import MempoolClient
from proxy.base.op_client import OpResourceClient


class BaseHandler:
    command: ClassVar[str | None] = None

    def __init__(self, cfg: Config) -> None:
        self._subcmd_dict: dict[str, Callable] = dict()
        self._cfg = cfg
        self._stop_task_list: list[Callable] = list()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, action) -> Self:
        return cls(cfg)

    async def execute(self, arg_space) -> int:
        try:
            if not (subcmd_handler := self._subcmd_dict.get(arg_space.subcommand, None)):
                print(f"Unknown command {self.command} {arg_space.subcommand}")
                return 1
            return await subcmd_handler(arg_space)
        finally:
            await asyncio.gather(*[task() for task in self._stop_task_list])

    @staticmethod
    def _gen_req_id() -> dict:
        return dict(timestamp=int(time.monotonic()))

    @cached_method
    async def _get_mp_client(self) -> MempoolClient:
        return await self._new_client(MempoolClient, self._cfg)

    @cached_method
    async def _get_op_client(self) -> OpResourceClient:
        return await self._new_client(OpResourceClient, self._cfg)

    @cached_method
    async def _get_sol_client(self) -> SolClient:
        return await self._new_client(SolClient, self._cfg)

    @cached_method
    async def _get_core_api_client(self) -> CoreApiClient:
        return await self._new_client(CoreApiClient, self._cfg, await self._get_sol_client())

    async def _new_client(self, client_type: type, *args):
        client = client_type(*args)

        async def _stop():
            await client.stop()

        self._stop_task_list.append(_stop)

        await client.start()
        return client

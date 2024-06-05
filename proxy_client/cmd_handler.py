from __future__ import annotations

from common.cmd_client.cmd_handler import BaseCmdHandler
from common.utils.cached import cached_method
from proxy.base.mp_client import MempoolClient
from proxy.base.op_client import OpResourceClient


class BaseNPCmdHandler(BaseCmdHandler):
    @cached_method
    async def _get_mp_client(self) -> MempoolClient:
        return await self._new_client(MempoolClient, self._cfg)

    @cached_method
    async def _get_op_client(self) -> OpResourceClient:
        return await self._new_client(OpResourceClient, self._cfg)

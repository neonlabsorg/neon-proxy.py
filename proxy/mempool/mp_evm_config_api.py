from typing import ClassVar

from common.neon_rpc.api import EvmConfigModel
from .server_abc import MempoolApi


class MpEvmCfgApi(MempoolApi):
    name: ClassVar[str] = "Mempool::NeonEvmConfig"

    @MempoolApi.method(name="getEvmConfig")
    async def get_evm_cfg(self) -> EvmConfigModel:
        return await self._server.get_evm_cfg()

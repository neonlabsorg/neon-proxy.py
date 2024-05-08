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
from ..base.mp_client import MempoolClient
from ..base.op_api import OP_RESOURCE_ENDPOINT
from ..base.server import BaseProxyServer, BaseProxyComponent


class OpResourceComponent(BaseProxyComponent):
    def __init__(self, server: OpResourceServerAbc) -> None:
        super().__init__(server)
        self._server = server


class OpResourceApi(OpResourceComponent, AppDataApi):
    def __init__(self, server: OpResourceServerAbc) -> None:
        AppDataApi.__init__(self)
        OpResourceComponent.__init__(self, server)


class OpResourceServerAbc(BaseProxyServer, abc.ABC):
    def __init__(self, cfg: Config, core_api_client: CoreApiClient, sol_client: SolClient, mp_client: MempoolClient):
        super().__init__(cfg, core_api_client, sol_client)
        self._mp_client = mp_client

    def _add_api(self, api: OpResourceApi) -> Self:
        return self.add_api(api, endpoint=OP_RESOURCE_ENDPOINT)

    @abc.abstractmethod
    async def get_signer_list(self) -> tuple[SolSigner, ...]: ...

    async def get_evm_cfg(self) -> EvmConfigModel:
        evm_cfg = await self._mp_client.get_evm_cfg()
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.protocol_version)
        return evm_cfg

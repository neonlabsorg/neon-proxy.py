from typing import ClassVar

from common.config.constants import NEON_PROXY_PKG_VER
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon_rpc.cmd_client import NeonCmdClient
from common.utils.pydantic import HexUIntField
from .server_abc import NeonProxyApi


class _RpcVersionResp(BaseJsonRpcModel):
    proxy: str
    evm: str
    core: str
    cli: str
    solana: str


class NpVersionApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::Version"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cmd_client = NeonCmdClient(self._cfg)

    @NeonProxyApi.method(name=["neon_cliVersion", "neon_cli_version"])
    async def neon_cmd_client_version(self) -> str:
        return await self._cmd_client.get_version()

    @NeonProxyApi.method(name="neon_coreVersion")
    async def neon_core_api_version(self) -> str:
        return await self._core_api_client.get_core_api_version()

    @NeonProxyApi.method(name=["neon_evmVersion", "web3_clientVersion", "neon_evm_version"])
    async def neon_evm_version(self) -> str:
        evm_cfg = await self.get_evm_cfg()
        return evm_cfg.package_version

    @NeonProxyApi.method(name=["neon_proxyVersion", "neon_proxy_version"])
    def neon_proxy_version(self) -> str:
        return NEON_PROXY_PKG_VER

    @NeonProxyApi.method(name="neon_solanaVersion")
    async def neon_solana_version(self) -> str:
        return await self._sol_client.get_version()

    @NeonProxyApi.method(name="neon_versions")
    async def neon_versions(self) -> _RpcVersionResp:
        return _RpcVersionResp(
            proxy=NEON_PROXY_PKG_VER,
            evm=await self.neon_evm_version(),
            core=await self.neon_core_api_version(),
            cli=await self.neon_cmd_client_version(),
            solana=await self.neon_solana_version(),
        )

    @NeonProxyApi.method(name="eth_chainId")
    def get_eth_chain_id(self, ctx: HttpRequestCtx) -> HexUIntField:
        return self.get_chain_id(ctx)

    @NeonProxyApi.method(name="net_version")
    async def get_net_version(self) -> HexUIntField:
        gas_price = await self._server.get_gas_price()
        return gas_price.default_token.chain_id

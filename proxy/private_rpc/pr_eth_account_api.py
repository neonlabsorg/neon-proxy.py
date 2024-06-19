from typing import ClassVar

from common.ethereum.hash import EthAddressField
from common.http.utils import HttpRequestCtx
from .server_abc import PrivateRpcApi


class PrEthAccountApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::EthAccount"

    @PrivateRpcApi.method(name="eth_accounts")
    async def eth_accounts(self, ctx: HttpRequestCtx) -> list[EthAddressField]:
        eth_address_list = await self._op_client.get_eth_address_list({"req_id": ctx.ctx_id})
        return [a.eth_address for a in eth_address_list]

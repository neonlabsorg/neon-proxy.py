from typing import ClassVar

from common.neon.account import NeonAccount
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddressField
from common.ethereum.transaction import EthTxField
from common.http.utils import HttpRequestCtx
from common.utils.format import hex_to_bytes
from .server_abc import PrivateRpcApi


class PrEthSignApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::EthSign"

    @PrivateRpcApi.method(name="eth_sign")
    async def eth_sign(self, ctx: HttpRequestCtx, eth_address: EthAddressField, data: str) -> str:
        if (NeonAccount.from_raw(eth_address, ctx.chain_id)) is None:
            raise EthError(message="signer not found")

        data = hex_to_bytes(data)
        message = str.encode(f"\x19Ethereum Signed Message:\n{len(data)}") + data
        response = await self._op_client.sign_eth_message(ctx.ctx_id, eth_address, message)

        if response.error:
            raise EthError(message=response.error)

        return response.signed_message

    @PrivateRpcApi.method(name="eth_signTransaction")
    async def eth_sign_tx(self, ctx: HttpRequestCtx, tx: EthTxField, eth_address: EthAddressField) -> str:
        if (NeonAccount.from_raw(eth_address, ctx.chain_id)) is None:
            raise EthError(message="signer not found")

        chain_id = tx.chain_id if tx.has_chain_id else await self._get_default_chain_id()
        response = await self._op_client.sign_eth_tx(ctx.ctx_id, tx, eth_address, chain_id)

        if response.error:
            raise EthError(message=response.error)

        return response.signed_tx

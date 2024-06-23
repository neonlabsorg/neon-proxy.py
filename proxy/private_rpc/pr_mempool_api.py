from typing import ClassVar

from common.ethereum.hash import EthAddressField
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.transaction_model import NeonTxModel
from .server_abc import PrivateRpcApi
from ..base.rpc_api import RpcEthTxResp


class _RpcTxPoolResp(BaseJsonRpcModel):
    pending: dict[EthAddressField, dict[int, RpcEthTxResp]]
    queued: dict[EthAddressField, dict[int, RpcEthTxResp]]


class PrMempoolApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::Mempool"

    @PrivateRpcApi.method(name="txpool_content")
    async def txpool_content(self, ctx: HttpRequestCtx) -> _RpcTxPoolResp:
        ctx_id = self._get_ctx_id(ctx)
        chain_id = self._get_chain_id(ctx)
        txpool_content = await self._mp_client.get_content(ctx_id, chain_id)
        return _RpcTxPoolResp(
            pending=self._get_queue(txpool_content.pending_list),
            queued=self._get_queue(txpool_content.queued_list),
        )

    @staticmethod
    def _get_queue(tx_list: list[NeonTxModel]) -> dict[EthAddressField, dict[int, RpcEthTxResp]]:
        sender_addr = EthAddressField.default()
        sender_pool: dict[int, RpcEthTxResp] = dict()
        sender_pool_dict: dict[EthAddressField, dict[int, RpcEthTxResp]] = dict()
        for tx in tx_list:
            if sender_addr != tx.from_address:
                if sender_pool:
                    sender_pool_dict[sender_addr] = sender_pool
                    sender_pool = dict()
                sender_addr = tx.from_address

            sender_pool[tx.nonce] = RpcEthTxResp.from_raw(tx)

        if not sender_addr.is_empty:
            sender_pool_dict[sender_addr] = sender_pool

        return sender_pool_dict

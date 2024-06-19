from typing import ClassVar

from common.http.utils import HttpRequestCtx
from .server_abc import PrivateRpcApi
from ..base.mp_client import MpTxPoolContentResp


class PrMempoolApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::Mempool"

    @PrivateRpcApi.method(name="txpool_content")
    async def txpool_content(self, ctx: HttpRequestCtx) -> MpTxPoolContentResp:
        return await self._mp_client.get_content(ctx.ctx_id)

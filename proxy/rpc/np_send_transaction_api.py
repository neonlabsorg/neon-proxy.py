import logging
from typing import ClassVar

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.hash import EthTxHashField
from common.http.utils import HttpRequestCtx
from common.utils.cached import cached_property
from .server_abc import NeonProxyApi
from ..base.rpc_transaction_executor import RpcNeonTxExecutor

_LOG = logging.getLogger(__name__)


class NpExecTxApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::ExecuteTransaction"

    @cached_property
    def _tx_executor(self) -> RpcNeonTxExecutor:
        return RpcNeonTxExecutor(self._server)

    @NeonProxyApi.method(name="eth_sendRawTransaction")
    async def send_raw_tx(self, ctx: HttpRequestCtx, raw_tx: EthBinStrField) -> EthTxHashField:
        return await self._tx_executor.send_neon_tx(ctx, raw_tx.to_bytes())

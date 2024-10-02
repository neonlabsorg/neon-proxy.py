from typing import ClassVar

from common.solana.transaction_model import SolTxModel
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import (
    OpSignerKeyListResp,
    OpGetSignerKeyListRequest,
    OpSignSolTxListRequest,
    OpSolTxListResp,
    OpDestroyHolderRequest,
    OpDestroyHolderResp,
)


class OpSolSignApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::SolSign"

    @OpResourceApi.method(name="getSignerKeyList")
    async def get_signer_key_list(self, request: OpGetSignerKeyListRequest) -> OpSignerKeyListResp:
        with logging_context(**request.req_id):
            return OpSignerKeyListResp(signer_key_list=list(self._op_resource_mng.get_signer_key_list()))

    @OpResourceApi.method(name="signSolanaTransactionList")
    async def sign_sol_tx_list(self, request: OpSignSolTxListRequest) -> OpSolTxListResp:
        with logging_context(**request.req_id):
            tx_list = tuple([model.tx for model in request.tx_list])
            tx_list = await self._op_resource_mng.sign_tx_list(request.owner, tx_list)
            return OpSolTxListResp(tx_list=[SolTxModel.from_raw(tx) for tx in tx_list])

    @OpResourceApi.method(name="destroyHolder")
    async def destroy_holder(self, request: OpDestroyHolderRequest) -> OpDestroyHolderResp:
        with logging_context(**request.req_id):
            result = self._op_resource_mng.destroy_holder(request.owner, request.holder)
            return OpDestroyHolderResp(result=result)

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import (
    OpGetResourceRequest,
    OpResourceModel,
    OpResourceResp,
    OpFreeResourceRequest,
    OpGetSolTokenAddressRequest,
    OpSolTokenAddressModel,
)


class OpAcquireResourceApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::AcquireResource"

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

    @OpResourceApi.method(name="getOperatorResource")
    def get_resource(self, request: OpGetResourceRequest) -> OpResourceModel:
        with logging_context(tx=request.tx_id):
            return self._op_resource_mng.get_resource(request.chain_id)

    @OpResourceApi.method(name="freeOperatorResource")
    def free_resource(self, request: OpFreeResourceRequest) -> OpResourceResp:
        with logging_context(tx=request.tx_id):
            self._op_resource_mng.free_resource(request.is_good, request.resource)
            return OpResourceResp(result=True)

    @OpResourceApi.method(name="getOperatorTokenAddress")
    def get_token_address(self, request: OpGetSolTokenAddressRequest) -> OpSolTokenAddressModel:
        with logging_context(tx=request.tx_id):
            owner_token_addr = self._op_resource_mng.get_sol_token_address(request.owner, request.chain_id)
            return OpSolTokenAddressModel(owner=request.owner, token_sol_address=owner_token_addr)

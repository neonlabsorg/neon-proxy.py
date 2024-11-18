from typing import ClassVar

from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import (
    OpGetResourceRequest,
    OpResourceModel,
    OpResourceResp,
    OpFreeResourceRequest,
    OpGetTokenSolAddressRequest,
    OpTokenSolAddressModel,
    OpGetActiveOperatorKey,
)


class OpAcquireResourceApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::AcquireResource"

    @OpResourceApi.method(name="getOperatorResource")
    def get_resource(self, request: OpGetResourceRequest) -> OpResourceModel:
        with logging_context(**request.req_id):
            return self._op_resource_mng.get_resource(request.owner, request.holder_address, request.chain_id)

    @OpResourceApi.method(name="getActiveOperatorKey")
    def get_active_key(self, request: OpGetActiveOperatorKey) -> OpResourceModel:
        with logging_context(**request.req_id):
            owner = self._op_resource_mng.get_active_operator()
            eth_addr, token_sol_addr = self._op_resource_mng.get_token_address(owner, request.chain_id)
            return OpResourceModel(
                owner=owner,
                eth_address=eth_addr,
                token_sol_address=token_sol_addr,
                holder_address=SolPubKey.default(),
                resource_id=OpResourceModel.EmptyResourceId,
                chain_id=request.chain_id,
            )

    @OpResourceApi.method(name="freeOperatorResource")
    async def free_resource(self, request: OpFreeResourceRequest) -> OpResourceResp:
        with logging_context(**request.req_id):
            if request.resource.is_empty:
                return OpResourceResp(result=True)

            await self._op_resource_mng.free_resource(request.is_good, request.resource)
            return OpResourceResp(result=True)

    @OpResourceApi.method(name="getOperatorTokenAddress")
    def get_token_address(self, request: OpGetTokenSolAddressRequest) -> OpTokenSolAddressModel:
        with logging_context(**request.req_id):
            eth_addr, token_sol_addr = self._op_resource_mng.get_token_address(request.owner, request.chain_id)
            return OpTokenSolAddressModel(owner=request.owner, eth_address=eth_addr, token_sol_address=token_sol_addr)

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import OpWithdrawTokenRequest, OpWithdrawTokenResp


class OpBalanceApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::Balance"

    @OpResourceApi.method(name="withdrawEarnedTokens")
    async def withdraw(self, request: OpWithdrawTokenRequest) -> OpWithdrawTokenResp:
        # TODO: complete logic
        with logging_context(**request.req_id):
            await self._op_resource_mng.withdraw()
            return OpWithdrawTokenResp(total_amount_dict=dict())

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

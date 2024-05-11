from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import OpSignerKeyListResp, OpGetSignerKeyListRequest


class OpSignerKeyApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::SignerKey"

    @OpResourceApi.method(name="getSignerKeyList")
    async def get_signer_key_list(self, request: OpGetSignerKeyListRequest) -> OpSignerKeyListResp:
        with logging_context(**request.req_id):
            return OpSignerKeyListResp(signer_key_list=list(self._op_resource_mng.get_signer_key_list()))

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

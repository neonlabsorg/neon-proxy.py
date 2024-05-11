from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .alt_destroyer import SolAltDestroyer
from .server_abc import ExecutorApi
from ..base.ex_api import DestroyAltListRequest, DestroyAltListResp


class SolAltApi(ExecutorApi):
    name: ClassVar[str] = "Executor::AddressLookupTable"

    @ExecutorApi.method(name="destroyAltList")
    async def _destroy_stuck_alt_list(self, request: DestroyAltListRequest) -> DestroyAltListResp:
        with logging_context(**request.req_id):
            self._sol_alt_destroyer.extend_alt_list(request.alt_list)
            return DestroyAltListResp(result=True)

    @cached_property
    def _sol_alt_destroyer(self) -> SolAltDestroyer:
        return self._server._sol_alt_destroyer  # noqa

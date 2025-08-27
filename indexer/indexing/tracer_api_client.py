from __future__ import annotations

import logging
from typing import Sequence, ClassVar

from common.config.config import Config
from common.jsonrpc.client import JsonRpcClient

_LOG = logging.getLogger(__name__)

class TracerApiClient(JsonRpcClient):
    name: ClassVar[str] = "TracerApiClient"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, None)
        self._tracerdb_url: str | None = cfg.tracerdb_url

        if self._tracerdb_url:
            self.connect(base_url=self._tracerdb_url)
            self.set_timeout_sec(120).set_max_retry_cnt(30)

    async def get_max_slot(self) -> int | None:
        if not self._tracerdb_url:
            return None

        try:
            return await self._get_last_received_slot()
        except BaseException as exc:
            _LOG.error("error on getting last received slot from TracerDB", exc_info=exc)

    @staticmethod
    def _rpc_error_handler(method: str, code: int, message: str, error_list: Sequence[str] | None) -> str | None:
        _LOG.error("TraverDB RPC Error: %d (%s); Error list: %s", code, message, ', '.join(error_list or []))
        return None

    @JsonRpcClient.method(name="get_last_received_slot")
    async def _get_last_received_slot(self) -> int: ...

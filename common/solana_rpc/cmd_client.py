from __future__ import annotations

import logging
from typing import Final

from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..utils.async_cmd_client import AsyncCmdClient, Process

_LOG = logging.getLogger(__name__)


class SolCmdClient(AsyncCmdClient):
    _keypair_prefix: Final[str] = "Keypair Path: "

    def __init__(self, cfg: Config) -> None:
        super().__init__("solana", cfg.debug_cmd_line)
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(self._cfg)

    async def _run_cmd_client(self, arg_list: list[str]) -> Process:
        sol_url = self._cfg.random_sol_url
        arg_list = ["--url", sol_url] + arg_list
        return await super()._run_cmd_client(arg_list)

    async def get_keypair_file(self) -> str | None:
        process = await self._run_cmd_client(["config", "get"])
        _LOG.debug("read the solana config with the length %s", len(process.stdout))

        for line in process.stdout.splitlines():
            if line.startswith(self._keypair_prefix):
                return line[len(self._keypair_prefix):].strip()
        return None

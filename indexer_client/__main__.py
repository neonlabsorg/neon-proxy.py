from __future__ import annotations

import sys

from common.cmd_client.cmd_executor import BaseCmdExecutor
from common.config.config import Config
from .reindexer import ReIndexHandler


class CmdExecutor(BaseCmdExecutor):
    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, description="Client command line utility for NeonIndexer.")
        self._handler_type_list.append(ReIndexHandler)


def main() -> None:
    cfg = Config()
    cmd_executor = CmdExecutor(cfg)

    exit_code = cmd_executor.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

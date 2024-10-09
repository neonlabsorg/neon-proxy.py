from __future__ import annotations

import os
import sys

from common.cmd_client.cmd_executor import BaseCmdExecutor
from common.config.config import Config
from proxy_client.holder_cmd import HolderHandler
from .alt_cmd import AltHandler
from .operator_balance_cmd import OpBalanceHandler
from .operator_info_cmd import OpInfoHandler


class CmdExecutor(BaseCmdExecutor):
    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg, description="Client command line utility for NeonProxy.")
        self._handler_type_list.append(OpInfoHandler)
        self._handler_type_list.append(OpBalanceHandler)
        self._handler_type_list.append(AltHandler)
        self._handler_type_list.append(HolderHandler)

        self._parser.add_argument(
            "-i",
            "--core-api-ip",
            required=False,
            type=str,
            dest="core_api_ip",
            help="Host address of neon-core-api",
        )
        self._parser.add_argument(
            "-p",
            "--core-api-port",
            required=False,
            type=int,
            dest="core_api_port",
            help="Port of neon-core-api",
        )
        self._parser.add_argument(
            "-u",
            "--solana-url",
            type=str,
            dest="solana_url",
            help="Solana URL",
        )

    async def _before_exec_handler(self, arg_space) -> None:
        if arg_space.core_api_host:
            os.environ[self._cfg.neon_core_api_ip_name] = arg_space.core_api_host
        if arg_space.core_api_port:
            os.environ[self._cfg.neon_core_api_port_name] = str(arg_space.core_api_port)
        if arg_space.core_api_host or arg_space.core_api_port:
            os.environ[self._cfg.neon_core_api_server_cnt_name] = str(1)
        if arg_space.solana_url:
            os.environ[self._cfg.sol_url_name] = arg_space.solana_url

        self._cfg = Config()


def main() -> None:
    cfg = Config()
    cmd_executor = CmdExecutor(cfg)

    exit_code = cmd_executor.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

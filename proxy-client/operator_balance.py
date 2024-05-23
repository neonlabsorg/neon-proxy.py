from argparse import Namespace
from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from proxy.base.op_client import OpResourceClient
from .base_handler import BaseHandler


class OpBalanceHandler(BaseHandler):
    command: ClassVar[str] = "operator-balance"
    _withdraw: Final[str] = "withdraw"

    @classmethod
    def new_arg_parser(cls, cfg: Config, action) -> Self:
        self = cls(cfg)
        self._root_parser = action.add_parser(self.command)
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command", dest="subcommand", description="valid commands"
        )

        self._withdraw_parser = self._cmd_parser.add_parser(cls._withdraw)
        self._subcmd_dict[cls._withdraw] = self._withdraw_cmd
        return self

    async def _withdraw_cmd(self, _arg_space) -> int:
        op_client = OpResourceClient(self._cfg)

        try:
            await op_client.start()
            await op_client.withdraw()
        finally:
            await op_client.stop()
        return 0

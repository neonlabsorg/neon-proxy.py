import asyncio
import logging
from argparse import ArgumentParser

import uvloop

from .cmd_handler import BaseCmdHandler
from ..config.config import Config
from ..utils.json_logger import Logger

_LOG = logging.getLogger(__name__)


class BaseCmdExecutor:
    def __init__(self, cfg: Config, description: str) -> None:
        Logger.setup()
        self._cfg = cfg
        self._parser = parser = ArgumentParser(description=description)
        self._cmd_parser = parser.add_subparsers(title="command", dest="command", description="valid commands.")

        self._handler_type_list: list[type[BaseCmdHandler]] = list()
        self._handler_dict: dict[str, BaseCmdHandler] = dict()

    def run(self) -> int:
        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._init_handler_dict())

        arg_space = self._parser.parse_args()
        if arg_space.command is None:
            return 0

        if not (handler := self._handler_dict.get(arg_space.command, None)):
            _LOG.error("unknown command %s", arg_space.command)
            return 1

        exit_code = loop.run_until_complete(self._exec_handler(handler, arg_space))
        return exit_code

    async def _init_handler_dict(self) -> None:
        for _Handler in self._handler_type_list:
            assert _Handler.command not in self._handler_dict
            assert _Handler.command != BaseCmdHandler.command
            self._handler_dict[_Handler.command] = await _Handler.new_arg_parser(self._cfg, self._cmd_parser)

    @staticmethod
    async def _exec_handler(_handler: BaseCmdHandler, arg_parser) -> int:
        return await _handler.execute(arg_parser)

from __future__ import annotations

import argparse
import asyncio
import sys

import uvloop

from common.config.config import Config
from common.utils.json_logger import Logger
from .base_handler import BaseHandler
from .operator_balance import OpBalanceHandler


async def _run(_handler: BaseHandler, _arg_parser) -> int:
    return await _handler.execute(_arg_parser)


def main() -> None:
    Logger.setup()

    parser = argparse.ArgumentParser(description="Client command line utility for NeonProxy.")
    arg_parser = parser.add_subparsers(title="command", dest="command", description="valid commands")

    cfg = Config()
    handler_list = (OpBalanceHandler,)
    handler_dict: dict[str, BaseHandler] = dict()

    async def _init_handler_dict():
        for _Handler in handler_list:
            handler_dict[_Handler.command] = await _Handler.new_arg_parser(cfg, arg_parser)
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_init_handler_dict())

    arg_space = parser.parse_args()
    if arg_space.command is None:
        sys.exit(0)

    if not (handler := handler_dict.get(arg_space.command, None)):
        print(f"Unknown command {arg_space.command}", file=sys.stderr)
        sys.exit(1)

    exit_code = loop.run_until_complete(_run(handler, arg_space))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import sys

import uvloop

from common.config.config import Config
from .base_handler import BaseHandler
from .operator_balance import OpBalanceHandler


async def _run(_handler: BaseHandler, _arg_parser) -> int:
    return await _handler.execute(_arg_parser)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client command line utility for Neon Proxy.")
    arg_parser = parser.add_subparsers(title="command", dest="command", description="valid commands")

    cfg = Config()
    handler_list = (OpBalanceHandler,)
    handler_dict: dict[str, BaseHandler] = dict()

    for _Handler in handler_list:
        handler_dict[_Handler.command] = _Handler.new_arg_parser(cfg, arg_parser)

    arg_space = parser.parse_args()
    if not (handler := handler_dict.get(arg_space.command, None)):
        print(f"Unknown command {arg_space.command}", file=sys.stderr)
        sys.exit(1)

    exit_code = uvloop.run(_run(handler, arg_space))
    sys.exit(exit_code)

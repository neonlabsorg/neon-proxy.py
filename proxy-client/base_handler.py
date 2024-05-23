from __future__ import annotations

from typing import ClassVar, Callable

from typing_extensions import Self

from common.config.config import Config


class BaseHandler:
    command: ClassVar[str | None] = None

    def __init__(self, cfg: Config) -> None:
        self._subcmd_dict: dict[str, Callable] = dict()
        self._cfg = cfg

    @classmethod
    def new_arg_parser(cls, cfg: Config, action) -> Self:
        return cls(cfg)

    async def execute(self, arg_space) -> int:
        if not (subcmd_handler := self._subcmd_dict.get(arg_space.subcommand, None)):
            print(f"Unknown command {self.command} {arg_space.subcommand}")
            return 1
        return await subcmd_handler(arg_space)

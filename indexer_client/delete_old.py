import asyncio
import logging
import re
from typing import ClassVar, Self, Final

from common.cmd_client.cmd_handler import BaseCmdHandler
from common.config.config import Config
from common.db.db_connect import DbConnection
from common.utils.json_logger import logging_context
from indexer.db.indexer_db import IndexerDb
from indexer.stat.client import FakeStatClient

_LOG = logging.getLogger(__name__)


class DeleteOldBlockHandler(BaseCmdHandler):
    command: ClassVar[str] = "delete-old-blocks"
    _age_re: Final[re.Pattern] = re.compile(r"^(?:(\d+)y)?(?:(\d+)m)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?$")

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._cmd_parser = cmd_list_parser.add_parser(self.command, help="delete old Neon history.")
        self._cmd_parser.add_argument(
            "age",
            type=str,
            help="Age of the block to delete. ",
        )

        return self

    async def _exec_impl(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            if not (age_match := self._age_re.match(arg_space.age)):
                _LOG.error(
                    "age %s is invalid. The age should be in the format <Y>y<M>m<W>w<D>d<H>h. "
                    "For example: 1y3w5h means 1 year, 3 weeks, 5 hours.",
                    arg_space.age,
                )
                return 1

            def _to_int(value: str) -> int:
                return int(value) if value else 0

            age_list = age_match.groups()
            age = (
                _to_int(age_list[0]) * 365 * 24 +
                _to_int(age_list[1]) * 30 * 24 +
                _to_int(age_list[2]) * 7 * 24+
                _to_int(age_list[3]) * 24 +
                _to_int(age_list[4])
            ) * int(2.5 * 60 * 60)
            if age <= 0:
                _LOG.error("age %s should be greater than 0", arg_space.age)
                return 1

            stat_client = FakeStatClient(self._cfg)
            db: IndexerDb = await self._new_client(
                IndexerDb,
                self._cfg,
                DbConnection(self._cfg, stat_client),
            )

            stop_slot = await db.get_finalized_slot()
            start_slot = await db.get_earliest_slot()
            new_start_slot = stop_slot - age
            if new_start_slot <= 0:
                _LOG.error("there are no such old blocks in history")
                return 0

            if start_slot >= new_start_slot:
                _LOG.debug("start slot %s is less than the new start slot %s", start_slot, new_start_slot)
                return 0

            await db.delete_old_block(new_start_slot)
            await asyncio.sleep(3)
            return 0

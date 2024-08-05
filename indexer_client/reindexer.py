import asyncio
import logging
from typing import ClassVar, Callable

from typing_extensions import Self

from common.cmd_client.cmd_handler import BaseCmdHandler
from common.config.config import Config
from common.db.db_connect import DbConnection
from common.solana.commit_level import SolCommit
from common.solana_rpc.not_empty_block import SolNotEmptyBlockFinder
from common.utils.json_logger import logging_context
from indexer.db.indexer_db import IndexerDb, IndexerDbSlotRange
from indexer.indexing.indexer import Indexer
from indexer.stat.client import StatClient

_LOG = logging.getLogger(__name__)


class ReIndexHandler(BaseCmdHandler):
    command: ClassVar[str] = "reindex"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._cmd_parser = cmd_list_parser.add_parser(self.command, help="reindexing Neon history.")
        self._cmd_parser.add_argument(
            "from_slot",
            type=int,
            help=(
                "start reindexing from this block. "
                "IMPORTANT! If you know the block number with a Neon receipt, "
                "you should decrease this number on ~100 blocks, "
                "because the Neon transaction has the preparation stage (WriteToHolder, Create/Extend ALT)"
            ),
        )
        self._cmd_parser.add_argument(
            "to_slot",
            type=int,
            help=(
                "stop reindexing in this block. "
                "IMPORTANT! If you know the block number with a Neon receipt, "
                "you should increase this number on ~2000 blocks, "
                "if the Neon transaction used many accounts and there were and ALT."
            ),
        )

        return self

    async def _exec_impl(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            if arg_space.from_slot > arg_space.to_slot:
                _LOG.error(
                    "from-block %s should be bigger than to-block %s",
                    arg_space.from_slot,
                    arg_space.to_slot,
                )
                return 1

            sol_client = await self._get_sol_client()
            core_api_client = await self._get_core_api_client()

            first_slot = await sol_client.get_first_slot()
            if first_slot > arg_space.from_slot:
                _LOG.error(
                    "from-block %s is less than the first available slot on Solana %s",
                    arg_space.from_slot,
                    first_slot,
                )
                return 1

            finalized_slot = await sol_client.get_slot(SolCommit.Finalized)
            if finalized_slot < arg_space.to_slot:
                _LOG.error(
                    "to-slot %s is bigger than the finalized slot on Solana %s",
                    arg_space.to_slot,
                    finalized_slot,
                )
                return 1

            block_finder = SolNotEmptyBlockFinder(
                sol_client,
                start_slot=arg_space.from_slot,
                stop_slot=arg_space.to_slot,
            )
            start_slot = await block_finder.find_slot()
            if start_slot >= arg_space.to_slot:
                _LOG.error(
                    "start slot %s should be bigger than to-block %s",
                    start_slot,
                    arg_space.to_slot,
                )
                return 1

            slot_range = IndexerDbSlotRange(
                f"client:reindex:{arg_space.from_slot}:{arg_space.to_slot}",
                start_slot,
                start_slot,
                stop_slot=arg_space.to_slot,
                term_slot=arg_space.to_slot,
            )

            stat_client = _FakeStatClient(self._cfg)
            db = await self._new_client(IndexerDb, self._cfg, DbConnection(self._cfg, stat_client), slot_range)

            indexer = Indexer(self._cfg, sol_client, core_api_client, None, stat_client, db)
            await indexer.run()
            await asyncio.sleep(1)
            return 0


class _FakeStatClient(StatClient):
    def __init__(self, cfg: Config) -> None:  # noqa
        self._cfg = cfg

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def _put_to_queue(self, call: Callable, data) -> None:
        pass

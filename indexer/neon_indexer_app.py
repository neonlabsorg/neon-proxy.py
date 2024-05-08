import asyncio
import logging
import sys

import uvloop

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.db.db_connect import DbConnection
from common.solana_rpc.client import SolClient
from common.neon_rpc.client import CoreApiClient
from common.neon_rpc.server import CoreApiServer
from common.utils.json_logger import Logger
from .db.indexer_db import IndexerDb
from .indexing.indexer import Indexer

_LOG = logging.getLogger(__name__)


class NeonIndexerApp:
    def __init__(self):
        Logger.setup()
        cfg = Config()
        _LOG.info("running NeonIndexer with the config: %s", cfg.to_string())

        self._cfg = cfg
        self._msg_filter = LogMsgFilter(cfg)
        self._sol_client = SolClient(cfg)
        self._core_api_server = CoreApiServer(cfg)
        self._core_api_client = CoreApiClient(cfg=cfg, sol_client=self._sol_client)

    def start(self) -> int:
        if sys.version_info >= (3, 11):
            with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
                runner.run(self._run())
        else:
            uvloop.install()
            asyncio.run(self._run())
        return 0

    async def _run(self):
        try:
            self._core_api_server.start()

            _LOG.info("init db...")
            db_conn = DbConnection(self._cfg)
            db_conn.enable_debug_query()
            await db_conn.start()

            db = await IndexerDb.from_db_conn(self._cfg, db_conn)
            _LOG.info("init db done")

            indexer = Indexer(self._cfg, self._sol_client, self._core_api_client, db)
            await indexer.start()

            await db_conn.close()
        except BaseException as exc:
            _LOG.error("error on Indexer run", exc_info=exc, extra=self._msg_filter)

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
from .stat.client import StatClient
from .stat.server import StatServer

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

        self._db_conn = DbConnection(self._cfg)

        self._stat_server = StatServer(cfg)
        self._stat_client = StatClient(cfg)

    def start(self) -> int:
        uvloop.run(self._run())
        return 0

    async def _run(self):
        try:
            self._core_api_server.start()
            self._stat_server.start()

            db = await IndexerDb.from_db_conn(self._cfg, self._db_conn)
            indexer = Indexer(self._cfg, self._sol_client, self._core_api_client, self._stat_client, db)
            await indexer.start()

            await indexer.stop()

            self._stat_server.stop()
        except BaseException as exc:
            _LOG.error("error on Indexer run", exc_info=exc, extra=self._msg_filter)

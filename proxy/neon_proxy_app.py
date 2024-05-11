import logging

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.db.db_connect import DbConnection
from common.neon_rpc.client import CoreApiClient
from common.neon_rpc.server import CoreApiServer
from common.solana_rpc.client import SolClient
from common.utils.json_logger import Logger
from gas_tank.db.gas_less_accounts_db import GasLessAccountDb
from indexer.db.indexer_db_client import IndexerDbClient
from .base.ex_client import ExecutorClient
from .base.mp_client import MempoolClient
from .base.op_client import OpResourceClient
from .executor.server import ExecutorServer
from .mempool.server import MempoolServer
from .operator_resource.server import OpResourceServer
from .rpc.server import NeonProxy

_LOG = logging.getLogger(__name__)


class NeonProxyApp:
    def __init__(self):
        Logger.setup()
        cfg = Config()
        _LOG.info("running NeonProxy with the cfg: %s", cfg.to_string())

        self._msg_filter = LogMsgFilter(cfg)

        # Init Solana client
        sol_client = SolClient(cfg)

        # Init Indexer Db client
        db_conn = DbConnection(cfg)
        db = IndexerDbClient(cfg, db_conn)
        gas_tank = GasLessAccountDb(db_conn)

        # Init Core Api
        self._core_api_server = CoreApiServer(cfg)

        # Init clients
        core_api_client = CoreApiClient(cfg, sol_client)
        op_client = OpResourceClient(cfg)
        mp_client = MempoolClient(cfg)
        exec_client = ExecutorClient(cfg)

        # Init Executor server
        self._exec_server = ExecutorServer(
            cfg=cfg,
            core_api_client=core_api_client,
            sol_client=sol_client,
            mp_client=mp_client,
            op_client=op_client,
        )

        # Init Resource server
        self._op_server = OpResourceServer(
            cfg=cfg,
            core_api_client=core_api_client,
            sol_client=sol_client,
            mp_client=mp_client,
        )

        # Init Mempool
        self._mp_server = MempoolServer(
            cfg=cfg,
            core_api_client=core_api_client,
            sol_client=sol_client,
            exec_client=exec_client,
            op_client=op_client,
            db=db,
        )

        # Init external RPC API
        self._proxy_server = NeonProxy(
            cfg=cfg,
            core_api_client=core_api_client,
            sol_client=sol_client,
            mp_client=mp_client,
            db=db,
            gas_tank=gas_tank,
        )

    def start(self) -> int:
        try:
            self._core_api_server.start()
            self._exec_server.start()
            self._op_server.start()
            self._mp_server.start()
            self._proxy_server.start()

            self._mp_server.stop()
            self._op_server.stop()
            self._exec_server.stop()
            self._core_api_server.stop()
            return 0

        except BaseException as exc:
            _LOG.error("error on NeonProxy run", exc_info=exc, extra=self._msg_filter)
            return 1

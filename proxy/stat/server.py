from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.stat.api import RpcCallData
from common.stat.metric import StatRegistry, StatSummary, StatGauge
from common.stat.prometheus import PrometheusServer
from common.utils.process_pool import ProcessPool
from .api import STATISTIC_ENDPOINT, TxPoolData, TxFailData, TxDoneData


class RpcStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::RPC"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._request = StatSummary("request", "Request on public RPC", registry=registry)

    @AppDataApi.method(name="commitRpcCall")
    def on_rpc_call(self, data: RpcCallData) -> None:
        label = dict(
            service=data.service,
            method=data.method,
            is_error=data.is_error,
        )
        self._request.add(label, data.time_nsec / (10**9))


class TxPoolStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::Mempool"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._tx_done = StatSummary("tx_done", "Processed transactions ", registry=registry)
        self._tx_fail = StatSummary("tx_fail", "Failed transactions ", registry=registry)
        self._tx_pool = StatGauge("tx_pool_count", "Total transactions in mempool", registry=registry)
        self._tx_process = StatGauge("tx_process_count", "Total transactions in processing", registry=registry)
        self._tx_stuck_pool = StatGauge("tx_stuck_count", "Total stuck transactions in mempool", registry=registry)
        self._tx_stuck_process = StatGauge(
            "tx_stuck_process_count",
            "Total stuck transactions in processing",
            registry=registry,
        )

    @AppDataApi.method(name="commitTransactionDone")
    def on_tx_done(self, data: TxDoneData) -> None:
        label = {}
        self._tx_done.add(label, data.time_nsec / (10**9))

    @AppDataApi.method(name="commitTransactionFail")
    def on_tx_fail(self, data: TxFailData) -> None:
        label = {}
        self._tx_fail.add(label, data.time_nsec / (10**9))

    @AppDataApi.method(name="commitPool")
    def on_tx_pool(self, data: TxPoolData) -> None:
        for pool in data.scheduling_queue:
            self._tx_pool.set({"token": pool.token}, pool.queue_len)

        label = {}
        self._tx_process.set(label, data.processing_queue_len)
        self._tx_stuck_pool.set(label, data.stuck_queue_len)
        self._tx_stuck_process.set(label, data.processing_stuck_queue_len)


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        super().__init__(cfg)
        self._registry = registry
        self.listen(host="127.0.0.1", port=self._cfg.stat_port)

    def _register_handler_list(self) -> None:
        self._add_api(RpcStatApi(self._registry))
        self._add_api(TxPoolStatApi(self._registry))
        super()._register_handler_list()

    def _add_api(self, api: AppDataApi) -> None:
        self.add_api(api, endpoint=STATISTIC_ENDPOINT)


class StatServer(ProcessPool):
    def __init__(self, cfg: Config) -> None:
        super().__init__()
        self._registry = StatRegistry()
        self._metric_server = MetricServer(cfg, self._registry)
        self._prometheus_server = PrometheusServer(cfg, self._registry)

    def _on_process_start(self) -> None:
        self._metric_server.start()
        self._prometheus_server.start()

    def _on_process_stop(self) -> None:
        self._prometheus_server.stop()
        self._metric_server.stop()

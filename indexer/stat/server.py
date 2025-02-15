from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.stat.api import RpcCallData, MetricStatData, HealthCheckData, HealthErrorListFormatter, HealthErrorCode
from common.stat.health_error_registry import HealthErrorRegistry
from common.stat.metric import StatRegistry, StatGauge, stat_render
from common.stat.metric_rpc import RpcStatCollector
from common.stat.prometheus import PrometheusServer
from common.utils.process_pool import ProcessPool
from .api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat, STATISTIC_ENDPOINT


class RpcStatApi(AppDataApi, RpcStatCollector):
    name: ClassVar[str] = "IndexerStatistic::RPC"

    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        AppDataApi.__init__(self)
        RpcStatCollector.__init__(self, stat_registry, error_registry)

    @AppDataApi.method(name="commitRpcCall")
    def on_rpc_call(self, data: RpcCallData) -> None:
        RpcStatCollector.commit_rpc_call(self, data)


class BlockStatApi(AppDataApi):
    name: ClassVar[str] = "IndexerStatistic::Block"

    def __init__(self, cfg: Config, stat_registry: StatRegistry, error_registry: HealthErrorRegistry) -> None:
        super().__init__()
        self._cfg = cfg
        self._error_registry = error_registry
        self._block_start = StatGauge("block_start", "Started block number", registry=stat_registry)
        self._block_confirmed = StatGauge("block_confirmed", "Last confirmed block number", registry=stat_registry)
        self._block_finalized = StatGauge("block_finalized", "Last finalized block number", registry=stat_registry)
        self._block_parsed = StatGauge("block_parsed", "Last parsed block number", registry=stat_registry)
        self._block_stop = StatGauge("block_stop", "Stop block number", registry=stat_registry)
        self._block_term = StatGauge("block_term", "Termination block number", registry=stat_registry)
        self._block_tracer = StatGauge("block_tracer", "Last tracer block number", registry=stat_registry)
        self._corrupted_block_cnt = StatGauge(
            "corrupted_block_cnt",
            "Number of corrupted blocks",
            registry=stat_registry,
        )

        # set defaults
        label = {}
        self._block_tracer.set(label, 0)
        self._corrupted_block_cnt.set(label, 0)

    @AppDataApi.method(name="commitBlock")
    def on_block(self, data: NeonBlockStat) -> None:
        label = {}

        self._block_start.set(label, data.start_block)
        self._block_parsed.set(label, data.parsed_block)
        self._block_confirmed.set(label, data.confirmed_block)
        self._block_finalized.set(label, data.finalized_block)
        if data.corrupted_block_cnt > 0:
            self._corrupted_block_cnt.add({}, data.corrupted_block_cnt)
            self._error_registry.add_error(
                "BlockStorage",
                HealthErrorCode.CorruptedBlockError,
                f"Fail to parse a Solana block",
                dict(
                    blocksCount=data.corrupted_block_cnt,
                )
            )
        if data.tracer_block:
            self._block_tracer.set(label, data.tracer_block)

        lag_block_cnt = data.confirmed_block - data.parsed_block
        if lag_block_cnt > self._cfg.indexer_block_lag_to_warn:
            self._error_registry.add_error(
                "BlockStorage",
                HealthErrorCode.LagBlockError,
                f"Indexer lags behind Solana",
                dict(
                    blocksCount=lag_block_cnt,
                )
            )


    @AppDataApi.method(name="commitReindexBlock")
    def on_reindex_block(self, data: NeonReindexBlockStat) -> None:
        label = {"reindex": data.reindex_ident}

        self._block_start.set(label, data.start_block)
        self._block_parsed.set(label, data.parsed_block)
        self._block_stop.set(label, data.stop_block)
        self._block_term.set(label, data.term_block)
        if data.corrupted_block_cnt > 0:
            self._corrupted_block_cnt.add(label, data.corrupted_block_cnt)

    @AppDataApi.method(name="commitReindexDone")
    def on_done_reindex(self, data: NeonDoneReindexStat) -> None:
        label = {"reindex": data.reindex_ident}

        self._block_start.reset(label)
        self._block_parsed.reset(label)
        self._block_stop.reset(label)
        self._block_term.reset(label)


class MetricApi(AppDataApi):
    name: ClassVar[str] = "IndexerStatistic::MetricStat"

    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        super().__init__()
        self._stat_registry = stat_registry
        self._error_registry = error_registry

    @AppDataApi.method(name="getMetricStatistic")
    def on_metric_stat(self) -> MetricStatData:
        return stat_render(self._stat_registry)

    @AppDataApi.method(name="getHealthErrorList")
    def on_health_error_list(self) -> HealthCheckData:
        fmt = HealthErrorListFormatter(error_list=self._error_registry.get_health_error_list())
        return HealthCheckData(data=fmt.to_json())


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, stat_registry: StatRegistry, error_registry: HealthErrorRegistry) -> None:
        super().__init__(cfg)
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)
        self._add_api(RpcStatApi(stat_registry, error_registry))
        self._add_api(BlockStatApi(cfg, stat_registry, error_registry))
        self._add_api(MetricApi(stat_registry, error_registry))

    def _add_api(self, api: AppDataApi) -> None:
        self.add_api(api, endpoint=STATISTIC_ENDPOINT)


class StatServer(ProcessPool):
    def __init__(self, cfg: Config) -> None:
        super().__init__()
        self.set_process_cnt(2)
        self._idx = 0

        self._stat_registry = StatRegistry()
        self._error_registry = HealthErrorRegistry(cfg)
        self._metric_server = MetricServer(cfg, self._stat_registry, self._error_registry)
        self._prometheus_server = PrometheusServer(cfg, STATISTIC_ENDPOINT)

    def _on_process_start(self, idx: int) -> None:
        super()._on_process_start(idx)
        self._idx = idx
        if idx == 0:
            self._metric_server.start()
        else:
            self._prometheus_server.start()

    def _on_process_stop(self) -> None:
        if self._idx == 0:
            self._metric_server.stop()
        else:
            self._prometheus_server.stop()

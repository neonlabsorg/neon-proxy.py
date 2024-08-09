from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.stat.api import RpcCallData, MetricStatData
from common.stat.metric import StatRegistry, StatGauge, stat_render
from common.stat.metric_rpc import RpcStatCollector
from common.stat.prometheus import PrometheusServer
from common.utils.process_pool import ProcessPool
from .api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat, STATISTIC_ENDPOINT


class RpcStatApi(AppDataApi, RpcStatCollector):
    name: ClassVar[str] = "IndexerStatistic::RPC"

    def __init__(self, registry: StatRegistry):
        AppDataApi.__init__(self)
        RpcStatCollector.__init__(self, registry)

    @AppDataApi.method(name="commitRpcCall")
    def on_rpc_call(self, data: RpcCallData) -> None:
        RpcStatCollector.commit_rpc_call(self, data)


class BlockStatApi(AppDataApi):
    name: ClassVar[str] = "IndexerStatistic::Block"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._block_start = StatGauge("block_start", "Started block number", registry=registry)
        self._block_confirmed = StatGauge("block_confirmed", "Last confirmed block number", registry=registry)
        self._block_finalized = StatGauge("block_finalized", "Last finalized block number", registry=registry)
        self._block_parsed = StatGauge("block_parsed", "Last parsed block number", registry=registry)
        self._block_stop = StatGauge("block_stop", "Stop block number", registry=registry)
        self._block_term = StatGauge("block_term", "Termination block number", registry=registry)
        self._block_tracer = StatGauge("block_tracer", "Last tracer block number", registry=registry)
        self._corrupted_block_cnt = StatGauge("corrupted_block_cnt", "Number of corrupted blocks", registry=registry)

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
        if data.tracer_block:
            self._block_tracer.set(label, data.tracer_block)

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

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._registry = registry

    @AppDataApi.method(name="getMetricStatistic")
    def on_metric_stat(self) -> MetricStatData:
        return stat_render(self._registry)


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        super().__init__(cfg)
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)
        self._add_api(RpcStatApi(registry))
        self._add_api(BlockStatApi(registry))
        self._add_api(MetricApi(registry))

    def _add_api(self, api: AppDataApi) -> None:
        self.add_api(api, endpoint=STATISTIC_ENDPOINT)


class StatServer(ProcessPool):
    def __init__(self, cfg: Config) -> None:
        super().__init__()
        self.set_process_cnt(2)
        self._idx = 0

        self._registry = StatRegistry()
        self._metric_server = MetricServer(cfg, self._registry)
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

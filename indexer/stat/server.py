from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.stat.metric import StatRegistry, StatGauge, StatCounter
from common.stat.prometheus import PrometheusServer
from common.utils.process_pool import ProcessPool
from .api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat, NeonTxStat, STATISTIC_ENDPOINT


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

    @AppDataApi.method(name="commitBlock")
    def on_block(self, data: NeonBlockStat) -> None:
        label = {}

        self._block_start.set(label, data.start_block)
        self._block_parsed.set(label, data.parsed_block)
        self._block_confirmed.set(label, data.confirmed_block)
        self._block_finalized.set(label, data.finalized_block)
        self._block_tracer.set(label, data.tracer_block)

    @AppDataApi.method(name="commitReindexBlock")
    def on_reindex_block(self, data: NeonReindexBlockStat) -> None:
        label = {"reindex": data.reindex_ident}

        self._block_start.set(label, data.start_block)
        self._block_parsed.set(label, data.parsed_block)
        self._block_stop.set(label, data.stop_block)
        self._block_term.set(label, data.term_block)

    @AppDataApi.method(name="commitReindexDone")
    def on_done_reindex(self, data: NeonDoneReindexStat) -> None:
        label = {"reindex": data.reindex_ident}
        self._block_start.reset(label)
        self._block_parsed.reset(label)
        self._block_stop.reset(label)
        self._block_term.reset(label)


class TxStatApi(AppDataApi):
    name: ClassVar[str] = "IndexerStatistic::Transaction"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._tx_count = StatCounter(
            "tx_count",
            "Number of completed Neon transactions",
            registry=registry,
        )
        self._tx_count_by_type = StatCounter(
            "tx_count_by_type",
            "Number of completed Neon transactions by type",
            registry=registry,
        )

        self._tx_canceled = StatCounter(
            "tx_canceled",
            "Number of canceled Neon transactions",
            registry=registry,
        )

        self._tx_sol_expense = StatGauge(
            "tx_sol_spent",
            "LAMPORTs spent on transaction execution",
            registry=registry,
        )

        self._sol_tx_count = StatCounter(
            "tx_sol_count_by_type",
            "Number of solana transactions within by type",
            registry=registry,
        )

    @AppDataApi.method(name="commitTransaction")
    def on_commit_tx(self, data: NeonTxStat) -> None:
        label = {"type": data.tx_type}
        if data.completed_neon_tx_cnt:
            self._tx_count.add({}, data.completed_neon_tx_cnt)
            self._tx_count_by_type.add(label, data.completed_neon_tx_cnt)

        if data.canceled_neon_tx_cnt:
            self._tx_canceled.add({}, data.canceled_neon_tx_cnt)

        self._tx_sol_expense.add({}, data.sol_expense)
        self._sol_tx_count.add(label, data.sol_tx_cnt)


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        super().__init__(cfg)
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)
        self._add_api(BlockStatApi(registry))
        self._add_api(TxStatApi(registry))

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

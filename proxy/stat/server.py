from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.ethereum.hash import EthAddress
from common.solana.pubkey import SolPubKey
from common.solana_rpc.transaction_list_sender_stat import SolTxFailData, SolTxDoneData
from common.stat.api import RpcCallData, MetricStatData, HealthCheckData, HealthErrorListFormatter, HealthErrorCode
from common.stat.health_error_registry import HealthErrorRegistry
from common.stat.metric import StatRegistry, StatSummary, StatGauge, stat_render
from common.stat.metric_rpc import RpcStatCollector
from common.stat.prometheus import PrometheusServer
from common.utils.process_pool import ProcessPool
from .api import (
    OpEarnedTokenBalanceData,
    OpResourceHolderStatusData,
    OpExecTokenBalanceData,
    STATISTIC_ENDPOINT,
    NeonTxPoolData,
    NeonTxFailData,
    NeonTxDoneData,
)


class OpResourceStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::OpResource"

    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        super().__init__()

        self._error_registry = error_registry

        # Earned tokens balance

        self._earned_token_balance: dict[str, dict[EthAddress, int]] = dict()
        self._earned_token_balance_stat = StatGauge(
            "operator_earned_token_balance",
            "Operator earned token balance",
            registry=stat_registry,
        )

        # Holder account status

        self._holder_free_cnt: dict[SolPubKey, int] = dict()
        self._holder_used_cnt: dict[SolPubKey, int] = dict()
        self._holder_disabled_cnt: dict[SolPubKey, int] = dict()
        self._holder_blocked_cnt: dict[SolPubKey, int] = dict()

        self._holder_free_cnt_stat = StatGauge(
            "operator_resource_holder_free",
            "Operator holder accounts (free)",
            registry=stat_registry,
        )
        self._holder_used_cnt_stat = StatGauge(
            "operator_resource_holder_used",
            "Operator holder accounts (used)",
            registry=stat_registry,
        )
        self._holder_disabled_cnt_stat = StatGauge(
            "operator_resource_holder_disabled",
            "Operator holder accounts (disabled)",
            registry=stat_registry,
        )
        self._holder_blocked_addr_cnt_stat = StatGauge(
            "operator_resource_holder_blocked",
            "Operator holder accounts (blocked)",
            registry=stat_registry,
        )
        self._holder_total_cnt_stat = StatGauge(
            "operator_resource_holder_total",
            "Operator holder accounts (total)",
            registry=stat_registry,
        )

        # Execution tokens balance

        self._execution_token_balance: dict[SolPubKey, int] = {}
        self._execution_token_balance_stat = StatGauge(
            "operator_execution_token_balance",
            "Operator token balance for execution",
            registry=stat_registry,
        )

    @AppDataApi.method(name="commitOpEarnedTokensBalance")
    async def on_op_earned_tokens_balance(self, data: OpEarnedTokenBalanceData) -> None:
        if data.token_name not in self._earned_token_balance:
            self._earned_token_balance[data.token_name] = {}

        self._earned_token_balance[data.token_name][data.eth_address] = data.balance

        label = dict(token_name=data.token_name, eth_address=data.eth_address.to_string())
        self._earned_token_balance_stat.set(label, data.balance)

        label = dict(token_name=data.token_name)
        total_balance = sum(self._earned_token_balance[data.token_name].values())
        self._earned_token_balance_stat.set(label, total_balance)

    @AppDataApi.method(name="commitOpResourceHolderStatus")
    async def on_op_resource_holder_status(self, data: OpResourceHolderStatusData) -> None:
        self._holder_free_cnt[data.owner] = data.free_holder_cnt
        self._holder_used_cnt[data.owner] = data.used_holder_cnt
        self._holder_disabled_cnt[data.owner] = data.disabled_holder_cnt
        self._holder_blocked_cnt[data.owner] = data.blocked_holder_cnt

        label = dict(owner=data.owner.to_string())
        self._holder_free_cnt_stat.set(label, data.free_holder_cnt)
        self._holder_used_cnt_stat.set(label, data.used_holder_cnt)
        self._holder_disabled_cnt_stat.set(label, data.disabled_holder_cnt)
        self._holder_blocked_addr_cnt_stat.set(label, data.blocked_holder_cnt)
        self._holder_total_cnt_stat.set(
            label,
            data.free_holder_cnt + data.used_holder_cnt + data.disabled_holder_cnt + data.blocked_holder_cnt,
        )

        label = {}
        holder_free_cnt = sum(self._holder_free_cnt.values())
        holder_used_cnt = sum(self._holder_used_cnt.values())
        holder_disabled_cnt = sum(self._holder_disabled_cnt.values())
        holder_blocked_cnt = sum(self._holder_blocked_cnt.values())
        holder_total_cnt = holder_free_cnt + holder_used_cnt + holder_disabled_cnt + holder_blocked_cnt
        self._holder_free_cnt_stat.set(label, holder_free_cnt)
        self._holder_used_cnt_stat.set(label, holder_used_cnt)
        self._holder_disabled_cnt_stat.set(label, holder_disabled_cnt)
        self._holder_blocked_addr_cnt_stat.set(label, holder_blocked_cnt)
        self._holder_total_cnt_stat.set(label, holder_total_cnt)

        if holder_disabled_cnt:
            self._error_registry.add_error(
                "Holders",
                HealthErrorCode.DisabledHolderError,
                f"Resource manager has disabled holders",
                dict(
                    holdersCount=holder_disabled_cnt,
                    operatorKeyList=[k.to_string() for k in self._holder_disabled_cnt.keys()],
                ),
            )
        if holder_used_cnt > int((holder_free_cnt + holder_used_cnt) * 0.8):
            self._error_registry.add_error(
                "Holders",
                HealthErrorCode.UsedHolderError,
                "more than 80% of used holders",
                dict(
                    usedHolderCount=holder_used_cnt,
                    totalHolderCount=(holder_free_cnt + holder_used_cnt),
                ),
            )

    @AppDataApi.method(name="commitOpExecutionTokenBalance")
    async def on_op_exec_token_balance(self, data: OpExecTokenBalanceData) -> None:
        self._execution_token_balance[data.owner] = data.balance

        label = dict(owner=data.owner.to_string())
        self._execution_token_balance_stat.set(label, data.balance)

        label = {}
        total_balance = sum(self._execution_token_balance.values())
        self._execution_token_balance_stat.set(label, total_balance)


class RpcStatApi(AppDataApi, RpcStatCollector):
    name: ClassVar[str] = "ProxyStatistic::RPC"

    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        AppDataApi.__init__(self)
        RpcStatCollector.__init__(self, stat_registry, error_registry)

    @AppDataApi.method(name="commitRpcCall")
    async def on_rpc_call(self, data: RpcCallData) -> None:
        RpcStatApi.commit_rpc_call(self, data)


class NeonTxPoolStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::Mempool"

    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        super().__init__()
        self._error_registry = error_registry

        self._label = dict()
        self._tx_done = StatSummary("tx_done", "Processed Neon transactions ", registry=stat_registry)
        self._tx_fail = StatSummary("tx_fail", "Failed Neon transactions ", registry=stat_registry)
        self._tx_pool = StatGauge("tx_pool_count", "Total Neon transactions in mempool", registry=stat_registry)
        self._tx_process = StatGauge(
            "tx_process_count",
            "Total Neon transactions in processing",
            registry=stat_registry,
        )
        self._tx_stuck_pool = StatGauge(
            "tx_stuck_count",
            "Total stuck Neon transactions in mempool",
            registry=stat_registry,
        )
        self._tx_stuck_process = StatGauge(
            "tx_stuck_process_count",
            "Total stuck transactions in processing",
            registry=stat_registry,
        )

    @AppDataApi.method(name="commitNeonTransactionDone")
    async def on_tx_done(self, data: NeonTxDoneData) -> None:
        self._tx_done.add(self._label, data.time_nsec / pow(10, 9))

    @AppDataApi.method(name="commitNeonTransactionFail")
    async def on_tx_fail(self, data: NeonTxFailData) -> None:
        self._tx_fail.add(self._label, data.time_nsec / pow(10, 9))

    @AppDataApi.method(name="commitNeonTransactionPool")
    def on_tx_pool(self, data: NeonTxPoolData) -> None:
        for pool in data.scheduling_queue:
            self._tx_pool.set({"token": pool.token}, pool.queue_len)
            if pool.high_queue_len < pool.queue_len:
                self._error_registry.add_error(
                    "Mempool",
                    HealthErrorCode.FullMempoolError,
                    f"Too many transactions in a Mempool",
                    dict(
                        token=pool.token,
                        capacity=pool.max_queue_len,
                        size=pool.queue_len,
                    ),
                )

        self._tx_process.set(self._label, data.processing_queue_len)
        self._tx_stuck_pool.set(self._label, data.stuck_queue_len)
        self._tx_stuck_process.set(self._label, data.processing_stuck_queue_len)

        if data.stuck_queue_len > 100:
            self._error_registry.add_error(
                "Mempool",
                HealthErrorCode.StuckTxError,
                f"Too many stuck transactions in Mempool",
                dict(
                    transactionCount=data.stuck_queue_len,
                ),
            )


class MetricApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::MetricStat"

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


class SolTxStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::SolanaTransaction"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._label = dict()
        self._registry = registry
        self._tx_done = StatSummary("sol_tx_done", "Processed Solana transactions", registry=registry)
        self._tx_fail = StatSummary("sol_tx_fail", "Failed Solana transactions", registry=registry)

    @AppDataApi.method(name="commitSolanaTransactionDone")
    def on_tx_done(self, data: SolTxDoneData) -> None:
        self._tx_done.add(self._label, data.time_nsec / pow(10, 9))

    @AppDataApi.method(name="commitSolanaTransactionFail")
    def on_tx_fail(self, data: SolTxFailData) -> None:
        self._tx_fail.add(self._label, data.time_nsec / pow(10, 9))


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, stat_registry: StatRegistry, error_registry: HealthErrorRegistry) -> None:
        super().__init__(cfg)
        self._stat_registry = stat_registry
        self._error_registry = error_registry
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)

    def _register_handler_list(self) -> None:
        self._add_api(OpResourceStatApi(self._stat_registry, self._error_registry))
        self._add_api(RpcStatApi(self._stat_registry, self._error_registry))
        self._add_api(NeonTxPoolStatApi(self._stat_registry, self._error_registry))
        self._add_api(MetricApi(self._stat_registry, self._error_registry))
        self._add_api(SolTxStatApi(self._stat_registry))
        super()._register_handler_list()

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
        super()._on_process_stop()
        if self._idx == 0:
            self._metric_server.stop()
        else:
            self._prometheus_server.stop()

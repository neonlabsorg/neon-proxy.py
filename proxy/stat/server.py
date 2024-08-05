from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.ethereum.hash import EthAddress
from common.config.config import Config
from common.solana.pubkey import SolPubKey
from common.solana_rpc.transaction_list_sender_stat import SolTxFailData, SolTxDoneData
from common.stat.api import RpcCallData, MetricStatData
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

    def __init__(self, registry: StatRegistry):
        super().__init__()

        # Earned tokens balance

        self._earned_token_balance: dict[str, dict[EthAddress, int]] = {}
        self._earned_token_balance_stat = StatGauge(
            "operator_earned_token_balance", "Operator earned token balance", registry=registry
        )

        # Holder account status

        self._holder_free_cnt: dict[SolPubKey, int] = {}
        self._holder_used_cnt: dict[SolPubKey, int] = {}
        self._holder_disabled_cnt: dict[SolPubKey, int] = {}
        self._holder_blocked_cnt: dict[SolPubKey, int] = {}

        self._holder_free_cnt_stat = StatGauge(
            "operator_resource_holder_free", "Operator holder accounts (free)", registry=registry
        )
        self._holder_used_cnt_stat = StatGauge(
            "operator_resource_holder_used", "Operator holder accounts (used)", registry=registry
        )
        self._holder_disabled_cnt_stat = StatGauge(
            "operator_resource_holder_disabled", "Operator holder accounts (disabled)", registry=registry
        )
        self._holder_blocked_addr_cnt_stat = StatGauge(
            "operator_resource_holder_blocked", "Operator holder accounts (blocked)", registry=registry
        )
        self._holder_total_cnt_stat = StatGauge(
            "operator_resource_holder_total", "Operator holder accounts (total)", registry=registry
        )

        # Execution tokens balance

        self._execution_token_balance: dict[SolPubKey, int] = {}
        self._execution_token_balance_stat = StatGauge(
            "operator_execution_token_balance", "Operator token balance for execution",
            registry=registry
        )

    @AppDataApi.method(name="commitOpEarnedTokensBalance")
    def on_op_earned_tokens_balance(self, data: OpEarnedTokenBalanceData) -> None:
        if data.token_name not in self._earned_token_balance:
            self._earned_token_balance[data.token_name] = {}

        self._earned_token_balance[data.token_name][data.eth_address] = data.balance

        label = dict(token_name=data.token_name, eth_address=data.eth_address.to_string())
        self._earned_token_balance_stat.set(label, data.balance)

        label = dict(token_name=data.token_name)
        total_balance = sum(self._earned_token_balance[data.token_name].values())
        self._earned_token_balance_stat.set(label, total_balance)

    @AppDataApi.method(name="commitOpResourceHolderStatus")
    def on_op_resource_holder_status(self, data: OpResourceHolderStatusData) -> None:
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
        self._holder_free_cnt_stat.set(label, holder_free_cnt)
        self._holder_used_cnt_stat.set(label, holder_used_cnt)
        self._holder_disabled_cnt_stat.set(label, holder_disabled_cnt)
        self._holder_blocked_addr_cnt_stat.set(label, holder_blocked_cnt)
        self._holder_total_cnt_stat.set(
            label,
            holder_free_cnt + holder_used_cnt + holder_disabled_cnt + holder_blocked_cnt,
        )

    @AppDataApi.method(name="commitOpExecutionTokenBalance")
    def on_op_exec_token_balance(self, data: OpExecTokenBalanceData) -> None:
        self._execution_token_balance[data.owner] = data.balance

        label = dict(owner=data.owner.to_string())
        self._execution_token_balance_stat.set(label, data.balance)

        label = {}
        total_balance = sum(self._execution_token_balance.values())
        self._execution_token_balance_stat.set(label, total_balance)


class RpcStatApi(AppDataApi, RpcStatCollector):
    name: ClassVar[str] = "ProxyStatistic::RPC"

    def __init__(self, registry: StatRegistry):
        AppDataApi.__init__(self)
        RpcStatCollector.__init__(self, registry)

    @AppDataApi.method(name="commitRpcCall")
    def on_rpc_call(self, data: RpcCallData) -> None:
        RpcStatApi.commit_rpc_call(self, data)


class NeonTxPoolStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::Mempool"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._label = dict()
        self._tx_done = StatSummary("tx_done", "Processed Neon transactions ", registry=registry)
        self._tx_fail = StatSummary("tx_fail", "Failed Neon transactions ", registry=registry)
        self._tx_pool = StatGauge("tx_pool_count", "Total Neon transactions in mempool", registry=registry)
        self._tx_process = StatGauge("tx_process_count", "Total Neon transactions in processing", registry=registry)
        self._tx_stuck_pool = StatGauge("tx_stuck_count", "Total stuck Neon transactions in mempool", registry=registry)
        self._tx_stuck_process = StatGauge(
            "tx_stuck_process_count",
            "Total stuck transactions in processing",
            registry=registry,
        )

    @AppDataApi.method(name="commitNeonTransactionDone")
    def on_tx_done(self, data: NeonTxDoneData) -> None:
        self._tx_done.add(self._label, data.time_nsec / (10**9))

    @AppDataApi.method(name="commitNeonTransactionFail")
    def on_tx_fail(self, data: NeonTxFailData) -> None:
        self._tx_fail.add(self._label, data.time_nsec / (10**9))

    @AppDataApi.method(name="commitNeonTransactionPool")
    def on_tx_pool(self, data: NeonTxPoolData) -> None:
        for pool in data.scheduling_queue:
            self._tx_pool.set({"token": pool.token}, pool.queue_len)

        self._tx_process.set(self._label, data.processing_queue_len)
        self._tx_stuck_pool.set(self._label, data.stuck_queue_len)
        self._tx_stuck_process.set(self._label, data.processing_stuck_queue_len)


class MetricApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::MetricStat"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._registry = registry

    @AppDataApi.method(name="getMetricStatistic")
    def on_metric_stat(self) -> MetricStatData:
        return stat_render(self._registry)


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
        self._tx_done.add(self._label, data.time_nsec / (10 ** 9))

    @AppDataApi.method(name="commitSolanaTransactionFail")
    def on_tx_fail(self, data: SolTxFailData) -> None:
        self._tx_fail.add(self._label, data.time_nsec / (10 ** 9))


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        super().__init__(cfg)
        self._registry = registry
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)

    def _register_handler_list(self) -> None:
        self._add_api(OpResourceStatApi(self._registry))
        self._add_api(RpcStatApi(self._registry))
        self._add_api(NeonTxPoolStatApi(self._registry))
        self._add_api(MetricApi(self._registry))
        self._add_api(SolTxStatApi(self._registry))
        super()._register_handler_list()

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
        super()._on_process_stop()
        if self._idx == 0:
            self._metric_server.stop()
        else:
            self._prometheus_server.stop()

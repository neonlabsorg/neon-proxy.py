import logging
from typing import ClassVar

from common.app_data.server import AppDataServer, AppDataApi
from common.ethereum.hash import EthAddress
from common.http.utils import HttpRequestCtx
from common.config.config import Config
from common.solana.pubkey import SolPubKey
from common.stat.api import RpcCallData
from common.stat.metric import StatRegistry, StatSummary, StatGauge
from common.stat.prometheus import PrometheusServer
from common.utils.json_logger import logging_context
from common.utils.process_pool import ProcessPool

from .api import (
    OpEarnedTokenBalanceData,
    OpResourceHolderStatusData,
    OpExecutionTokenBalanceData,
    STATISTIC_ENDPOINT,
    TxPoolData,
    TxFailData,
    TxDoneData,
)

_LOG = logging.getLogger(__name__)


class OpResourceStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::OpResource"

    def __init__(self, registry: StatRegistry):
        super().__init__()

        # Earned tokens balance

        self._earned_token_balance: dict[str, dict[EthAddress, int]] = {}
        self._earned_token_balance_stat = StatGauge(
            "operator_earned_token_balance", "Operator earned token balance", registry=registry
        )

        # legacy
        self._neon_balance_stat = StatGauge(
            "operator_neon_balance", "Operator NEON balance", registry=registry
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
        # legacy
        self._sol_balance_stat = StatGauge(
            "operator_sol_balance", "Operator SOL balance", registry=registry
        )

    @AppDataApi.method(name="commitOpEarnedTokensBalance")
    def on_op_earned_tokens_balance(self, ctx: HttpRequestCtx, data: OpEarnedTokenBalanceData) -> None:
        with logging_context(method="commitOpEarnedTokensBalance", resp_time=ctx.process_time_msec):
            if data.token_name not in self._earned_token_balance:
                self._earned_token_balance[data.token_name] = {}

            self._earned_token_balance[data.token_name][data.eth_address] = data.balance

            label = dict(token_name=data.token_name, eth_address=data.eth_address.to_string())
            self._earned_token_balance_stat.set(label, data.balance)

            label = dict(token_name=data.token_name)
            total_balance = sum(self._earned_token_balance[data.token_name].values())
            self._earned_token_balance_stat.set(label, total_balance)

            if data.token_name == "NEON":
                label = dict(eth_address=data.eth_address.to_string())
                self._neon_balance_stat.set(label, data.balance)
                label = {}
                self._neon_balance_stat.set(label, total_balance)

            _LOG.info("done request >>>")

    @AppDataApi.method(name="commitOpResourceHolderStatus")
    def on_op_resource_holder_status(self, ctx: HttpRequestCtx, data: OpResourceHolderStatusData) -> None:
        with logging_context(method="commitOpResourceHolderStatus", resp_time=ctx.process_time_msec):
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

            _LOG.info("done request >>>")

    @AppDataApi.method(name="commitOpExecutionTokenBalance")
    def on_op_exec_token_balance(self, ctx: HttpRequestCtx, data: OpExecutionTokenBalanceData) -> None:
        with logging_context(method="commitOpExecutionTokenBalance", resp_time=ctx.process_time_msec):
            self._execution_token_balance[data.owner] = data.balance

            label = dict(owner=data.owner.to_string())
            self._execution_token_balance_stat.set(label, data.balance)
            self._sol_balance_stat.set(label, data.balance)

            label = {}
            total_balance = sum(self._execution_token_balance.values())
            self._execution_token_balance_stat.set(label, total_balance)
            self._sol_balance_stat.set(label, total_balance)

            _LOG.info("done request >>>")

class RpcStatApi(AppDataApi):
    name: ClassVar[str] = "ProxyStatistic::RPC"

    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._request = StatSummary("request", "Request on public RPC", registry=registry)

    @AppDataApi.method(name="commitRpcCall")
    def on_rpc_call(self, ctx: HttpRequestCtx, data: RpcCallData) -> None:
        with logging_context(method="commitRpcCall", resp_time=ctx.process_time_msec):
            label = dict(
                service=data.service,
                method=data.method,
                is_error=data.is_error,
            )
            self._request.add(label, data.time_nsec / (10**9))

            _LOG.info("done request >>>")


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
    def on_tx_done(self, ctx: HttpRequestCtx, data: TxDoneData) -> None:
        with logging_context(method="commitTransactionDone", resp_time=ctx.process_time_msec):
            label = {}
            self._tx_done.add(label, data.time_nsec / (10**9))

            _LOG.info("done request >>>")

    @AppDataApi.method(name="commitTransactionFail")
    def on_tx_fail(self, ctx: HttpRequestCtx, data: TxFailData) -> None:
        with logging_context(method="commitTransactionFail", resp_time=ctx.process_time_msec):
            label = {}
            self._tx_fail.add(label, data.time_nsec / (10**9))

            _LOG.info("done request >>>")

    @AppDataApi.method(name="commitPool")
    def on_tx_pool(self, ctx: HttpRequestCtx, data: TxPoolData) -> None:
        with logging_context(method="commitPool", resp_time=ctx.process_time_msec):
            for pool in data.scheduling_queue:
                self._tx_pool.set({"token": pool.token}, pool.queue_len)

            label = {}
            self._tx_process.set(label, data.processing_queue_len)
            self._tx_stuck_pool.set(label, data.stuck_queue_len)
            self._tx_stuck_process.set(label, data.processing_stuck_queue_len)

            _LOG.info("done request >>>")


class MetricServer(AppDataServer):
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        super().__init__(cfg)
        self._registry = registry
        self.listen(host=self._cfg.stat_ip, port=self._cfg.stat_port)

    def _register_handler_list(self) -> None:
        self._add_api(OpResourceStatApi(self._registry))
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

from .api import RpcCallData
from .health_error_registry import HealthErrorRegistry
from .metric import StatSummary, StatRegistry


class RpcStatCollector:
    def __init__(self, stat_registry: StatRegistry, error_registry: HealthErrorRegistry):
        self._request = StatSummary("request", "Requests on RPC endpoint", registry=stat_registry)
        self._error_registry = error_registry

    def commit_rpc_call(self, data: RpcCallData) -> None:
        label = dict()

        def _add_label(name: str, value):
            if value:
                label[name] = value

        time_sec = data.time_nsec / pow(10, 9)

        _add_label("service", data.service)
        _add_label("method", data.method)
        _add_label("is_error", data.is_error)
        _add_label("is_modification", data.is_modification)
        self._request.add(label, time_sec)

        if data.is_error:
            self._error_registry.add_error(data.service, data.error_message)

        if time_sec > 1.0:
            self._error_registry.add_error(data.service, f"Big response time {time_sec} seconds on {data.method}")

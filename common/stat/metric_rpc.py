from .api import RpcCallData, HealthErrorCode
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

        _add_label("exported_service", data.service)
        _add_label("method", data.method)
        _add_label("is_error", data.is_error)
        _add_label("is_modification", data.is_modification)
        self._request.add(label, time_sec)

        has_error = False
        if data.is_error:
            has_error = True
            self._error_registry.add_error(
                data.service,
                HealthErrorCode.RPCError,
                data.error_message,
                dict(
                    method=data.method,
                )
            )

        if time_sec > 1.0:
            has_error = True
            self._error_registry.add_error(
                data.service,
                HealthErrorCode.RPCBigTimeError,
                f"Big response time on {data.method}",
                dict(
                    method=data.method,
                    responseTime=time_sec,
                )
            )

        if not has_error:
            self._error_registry.add_good_time(data.service)

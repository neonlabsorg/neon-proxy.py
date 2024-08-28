from .api import RpcCallData
from .metric import StatSummary, StatRegistry


class RpcStatCollector:
    def __init__(self, registry: StatRegistry):
        super().__init__()
        self._request = StatSummary("request", "Requests on RPC endpoint", registry=registry)

    def commit_rpc_call(self, data: RpcCallData) -> None:
        label = dict()

        def _add_label(name: str, value):
            if value:
                label[name] = value

        _add_label("service", data.service)
        _add_label("method", data.method)
        _add_label("is_error", data.is_error)
        _add_label("is_modification", data.is_modification)

        self._request.add(label, data.time_nsec / (10**9))

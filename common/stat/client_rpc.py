import abc
import time
from dataclasses import dataclass

from typing_extensions import Self

from ..http.client import HttpClientRequest
from .api import RpcCallData


class RpcStatClient(abc.ABC):
    @abc.abstractmethod
    def commit_rpc_call(self, data: RpcCallData) -> None:
        pass


@dataclass
class RpcClientRequest(HttpClientRequest):
    _stat_client: RpcStatClient
    _stat_name: str
    _method: str
    _start_time_nsec: int
    
    @classmethod
    def from_raw(  # noqa
        cls,
        *,
        data: str,
        stat_client: RpcStatClient,
        stat_name: str,
        method: str,
     ) -> Self:
        return cls(
            data=data,
            path=None,
            header_dict=dict(),
            _stat_client=stat_client,
            _stat_name=stat_name,
            _method=method,
            _start_time_nsec=time.monotonic_ns(),
        )

    def commit_stat(self, *, is_error: bool) -> None:
        process_time_nsec = self.process_time_nsec
        self._start_time_nsec = time.monotonic_ns()

        stat = RpcCallData(
            service=self._stat_name,
            method=self._method,
            time_nsec=process_time_nsec,
            is_error=is_error,
        )
        self._stat_client.commit_rpc_call(stat)

    @property
    def process_time_nsec(self) -> int:
        if self._start_time_nsec:
            return time.monotonic_ns() - self._start_time_nsec
        return 0

    def __enter__(self) -> Self:
        self._start_time_ns = time.monotonic_ns()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> Self:
        self.commit_stat(is_error=exc_val is not None)

        if exc_val:
            raise
        return self

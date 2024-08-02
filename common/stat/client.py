from __future__ import annotations

import abc
import asyncio
import contextlib
import logging
from typing import Final, Callable

from common.config.config import Config
from common.stat.api import RpcCallData
from common.utils.json_logger import logging_context
from common.utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class BaseStatClient:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._send_queue: asyncio.Queue[tuple[Callable, BaseModel]] = asyncio.Queue()
        self._stop_event = asyncio.Event()
        self._send_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._send_task = asyncio.create_task(self._send_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._send_task:
            await self._send_task

    def _put_to_queue(self, call: Callable, data: BaseModel) -> None:
        if self._cfg.gather_stat:
            self._send_queue.put_nowait((call, data))

    async def _send_loop(self) -> None:
        sleep_sec: Final[float] = 0.3
        with logging_context(ctx="stat-client"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    await self._send_data()
                except BaseException as exc:
                    _LOG.warning("error on send data", exc_info=exc)

    async def _send_data(self) -> None:
        while not self._send_queue.empty():
            call, data = self._send_queue.get_nowait()
            await call(data)


class RpcStatClient(abc.ABC):
    def commit_rpc_call(self, data: RpcCallData) -> None:
        self._put_to_queue(self._commit_rpc_call, data)  # noqa

    @abc.abstractmethod
    async def _commit_rpc_call(self, data: RpcCallData) -> None:
        pass

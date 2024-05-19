import abc
import asyncio
import multiprocessing as _mp
import threading as _th

import uvloop as _uv
from typing_extensions import Self


class _Loop(_uv.Loop):
    def __init__(self) -> None:
        super().__init__()
        self._skip_run_forever = True

    def run_forever(self):
        if self._skip_run_forever:
            pass
        else:
            super().run_forever()

    def enable_run_forever(self):
        self._skip_run_forever = False


class _EventLoopPolicy(_uv.EventLoopPolicy):
    def __init__(self, loop: _Loop) -> None:
        super().__init__()
        self._skip_loop_factory = True
        self._loop = loop

    def _loop_factory(self) -> _uv.Loop:
        if self._skip_loop_factory:
            return self._loop
        return super()._loop_factory()

    def enable_loop_factory(self) -> None:
        self._skip_loop_factory = False


class ProcessPool(abc.ABC):
    def __init__(self) -> None:
        self._process_cnt = 1
        self._stop_event = _mp.Event()
        self._process_pool: list[_mp.Process] = list()

    def set_process_cnt(self, value: int) -> Self:
        assert value > 0
        self._process_cnt = value
        return self

    def start(self) -> None:
        self._process_pool = [_mp.Process(target=self._run) for _ in range(self._process_cnt)]
        for process in self._process_pool:
            process.start()

    def stop(self) -> None:
        self._stop_event.set()
        for process in self._process_pool:
            process.join()

    def _run(self) -> None:
        # it's just a crutch for Robyn server, that calls event_loop.run_forever() inside
        loop = _Loop()
        policy = _EventLoopPolicy(loop)
        asyncio.set_event_loop_policy(policy)
        asyncio.set_event_loop(loop)
        # complete configuring of the crutch for Robyn Server

        # start thread that wait for stop event from external process
        waiter = _th.Thread(target=self._wait_for_stop_event, args=[loop])
        waiter.start()

        self._on_process_start()

        # enable normal mode
        loop.enable_run_forever()
        policy.enable_loop_factory()
        # run asyncio loop
        loop.run_forever()
        # process received the stop event -> complete the work
        self._on_process_stop()

    def _wait_for_stop_event(self, loop: asyncio.AbstractEventLoop) -> None:
        self._stop_event.wait()
        loop.call_soon_threadsafe(loop.stop)

    @abc.abstractmethod
    def _on_process_start(self) -> None: ...

    @abc.abstractmethod
    def _on_process_stop(self) -> None: ...

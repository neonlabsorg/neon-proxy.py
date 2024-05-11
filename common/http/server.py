from __future__ import annotations

import abc
import asyncio
import logging
import os
import signal
import time
from multiprocessing import Process, Event
from typing import Callable, Awaitable, Union

import robyn as _rb
import robyn.router as _rt
from typing_extensions import Self

from .errors import HttpRouteError
from .utils import HttpMethod, HttpURL, HttpStrOrURL, HttpRequestCtx
from ..config.config import Config
from ..config.utils import LogMsgFilter, hide_sensitive_info

_LOG = logging.getLogger(__name__)

_HttpRoute = _rt.Route
_HttpFunctionInfo = _rt.FunctionInfo
_HttpProcessEvent = _rb.Events
_HttpRouteType = _rb.HttpMethod
_http_get_version = _rb.get_version
_http_pool = _rb.processpool
_http_status_code = _rb.status_codes

HttpRequest = _rb.Request
HttpResp = _rb.Response
HttpHeaderDict = _rb.Headers


class HttpServer(abc.ABC):
    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(self._cfg)

        self._host = "127.0.0.1"
        self._port = 8000

        self._proc_cnt = 1
        self._wrk_cnt = 1

        self._req_hdr_dict = HttpHeaderDict({})
        self._route_list: list[_HttpRoute] = list()

        self._pid: int | None = None
        self._recv_sig_num = signal.SIG_DFL
        self._stop_event = Event()

    @property
    def config(self) -> Config:
        return self._cfg

    @abc.abstractmethod
    def _register_handler_list(self) -> None: ...

    async def on_server_start(self) -> None: ...
    async def on_server_stop(self) -> None: ...

    def set_process_cnt(self, value: int) -> Self:
        self._proc_cnt = value
        return self

    def set_worker_cnt(self, value: int) -> Self:
        self._wrk_cnt = value
        return self

    def listen(self, *, host: str, port: int) -> Self:
        self._host = host
        self._port = port
        return self

    def add_post_route(self, endpoint: HttpStrOrURL, post_handler: HttpPostHandler) -> None:
        return _add_post_handler(self, endpoint, post_handler)

    def is_started(self) -> bool:
        return self._pid is not None

    def start(self) -> None:
        assert not self.is_started(), "Server is already started"

        # register http handlers
        self._register_handler_list()

        # run Robyn HTTP server
        self._pid = os.getpid()
        _LOG.info("starting Server(pid=%s) ...", self._pid)
        process_pool = _start_process_pool(self)

        # register signal handlers
        _register_term_signal_handler(self)
        _LOG.info("Server(pid=%s) is started", self._pid)

        # wait for signal or stop event ...
        while self._recv_sig_num == signal.SIG_DFL:
            if self._stop_event.wait(1.0):
                break
        else:
            _LOG.info("received signal %d in the process %d...", self._recv_sig_num, self._pid)

        _LOG.info("stopping Server(pid=%d)...", self._pid)
        _stop_process_pool(process_pool)
        _LOG.info("Server(pid=%d) is stopped", self._pid)

    def stop(self, wait_sec: float = 1.0) -> None:
        pid = os.getpid()
        _LOG.info("received stop event in the process: %d", pid)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_postpone_stop(self._stop_event, wait_sec))
        except RuntimeError:
            if pid == self._pid:
                _LOG.error("can't stop server in the same process: %s", pid)
            else:
                self._stop_event.set()

    @classmethod
    def _pack_json_resp(cls, ctx: HttpRequestCtx, body_json: str) -> HttpResp:
        return HttpResp(
            status_code=_http_status_code.HTTP_200_OK,
            description=body_json,
            headers=_create_headers(ctx),
        )

    def _pack_error_resp(self, ctx: HttpRequestCtx, exc: BaseException) -> HttpResp:
        msg = dict(
            message="error on {Path} from {IP}",
            Path=ctx.path,
            IP=ctx.ip_addr,
        )
        _LOG.error(msg, exc_info=exc)

        return HttpResp(
            status_code=_http_status_code.HTTP_500_INTERNAL_SERVER_ERROR,
            description=hide_sensitive_info(self._msg_filter, str(exc)),
            headers=_create_headers(ctx),
        )

    @classmethod
    def _pack_bad_route_resp(cls, ctx: HttpRequestCtx) -> HttpResp:
        return HttpResp(
            status_code=_http_status_code.HTTP_404_NOT_FOUND,
            description="The requested URL was not found on this server.",
            headers=_create_headers(ctx),
        )


HttpPostHandler = Union[
    Callable[[HttpServer, HttpRequestCtx], Awaitable[HttpResp]],
    Callable[[HttpServer, HttpRequestCtx], HttpResp],
    Callable[[HttpRequestCtx], Awaitable[HttpResp]],
    Callable[[HttpRequestCtx], HttpResp],
]


def _create_headers(ctx: HttpRequestCtx) -> HttpHeaderDict:
    hdr_dict = {
        "Content-Type": "application/text; charset=utf-8",
        "X-Process-Time": ctx.process_time_msec,
    }
    return HttpHeaderDict(hdr_dict)


def _register_term_signal_handler(self: HttpServer) -> None:
    def _signal_handler(_sig: int, _frame) -> None:
        if self._recv_sig_num == signal.SIG_DFL:
            self._recv_sig_num = _sig

    for sig in (signal.SIGINT, signal.SIGTERM):
        _LOG.info("register signal handler %d", sig)
        signal.signal(sig, _signal_handler)


def _start_process_pool(self: HttpServer) -> list[Process]:
    _LOG.info("Robyn HTTP Server v%s at the %s://%s:%d", _http_get_version(), "http", self._host, self._port)

    event_dict = {
        _HttpProcessEvent.STARTUP: _HttpFunctionInfo(_start_process_event(self), True, 0, {}, {}),
        _HttpProcessEvent.SHUTDOWN: _HttpFunctionInfo(_shutdown_process_event(self), True, 0, {}, {}),
    }

    pool_socket = _http_pool.SocketHeld(self._host, self._port)

    process_pool: list[Process] = _http_pool.init_processpool(
        directories=list(),
        request_headers=self._req_hdr_dict,
        routes=self._route_list,
        global_middlewares=list(),
        route_middlewares=list(),
        web_sockets=dict(),
        event_handlers=event_dict,
        socket=pool_socket,
        workers=self._wrk_cnt,
        processes=self._proc_cnt,
        response_headers=HttpHeaderDict({}),
    )

    return process_pool


def _start_process_event(self: HttpServer) -> Callable:
    async def _wrapper() -> None:
        pid = os.getpid()
        await self.on_server_start()
        _LOG.info("Worker(pid=%d) is started", pid)

    return _wrapper


def _shutdown_process_event(self: HttpServer) -> Callable:
    async def _wrapper() -> None:
        pid = os.getpid()
        await self.on_server_stop()
        _LOG.info("Worker(pid=%d) is stopped", pid)
        self._stop_event.set()

    return _wrapper


def _stop_process_pool(process_pool: list[Process]):
    has_alive_process = False
    for process in process_pool:
        if process.is_alive():
            has_alive_process = True
            os.kill(process.pid, signal.SIGINT)

    if has_alive_process:
        time.sleep(0.5)

    for process in process_pool:
        if process.is_alive():
            process.kill()

    for process in process_pool:
        process.join()


async def _postpone_stop(stop_event: Event, wait_sec: float) -> None:
    # Allow finish all postponed tasks
    _LOG.info("wait %s seconds before stopping server...", wait_sec)
    await asyncio.sleep(wait_sec)

    _LOG.info("send stop signal")
    stop_event.set()


def _add_post_handler(self: HttpServer, base_path: HttpStrOrURL, handler: HttpPostHandler) -> None:
    method = HttpMethod.from_handler(handler, allow_request_ctx=True)
    assert method.has_ctx

    assert issubclass(method.ReturnType, HttpResp), "Wrong return type of the HttpPostHandler"
    assert len(method.param_name_list) == 0, "HttpPostHandler can accept only one HttpRequestCtx"

    endpoint = HttpURL(base_path)
    assert not endpoint.is_absolute(), "Base_path should be relative"

    def _validate_resp(resp: HttpResp) -> HttpResp:
        assert isinstance(resp, HttpResp), f"Wrong response type {type(resp).__name__} != HttpResponse"
        return resp

    def _sync_wrapper(request: HttpRequest) -> HttpResp:
        ctx = HttpRequestCtx.from_raw(endpoint.path, request=request)
        args = (self, ctx,) if method.has_self else (ctx,)  # fmt: skip
        try:
            resp = handler(*args)
            return _validate_resp(resp)
        except HttpRouteError:
            return self._pack_bad_route_resp(ctx)
        except BaseException as exc:
            return self._pack_error_resp(ctx, exc)

    async def _async_wrapper(request: HttpRequest) -> HttpResp:
        ctx = HttpRequestCtx.from_raw(endpoint.path, request=request)
        args = (self, ctx,) if method.has_self else (ctx,)  # fmt: skip
        try:
            resp = await handler(*args)
            return _validate_resp(resp)
        except HttpRouteError:
            return self._pack_bad_route_resp(ctx)
        except BaseException as exc:
            return self._pack_error_resp(ctx, exc)

    _wrapper = _async_wrapper if method.is_async_def else _sync_wrapper
    wrapper_info = HttpMethod.from_handler(_wrapper, allow_request_ctx=False)
    param_dict = dict(wrapper_info.signature.parameters)
    func_info = _HttpFunctionInfo(_wrapper, method.is_async_def, len(param_dict), param_dict, dict())

    route = _HttpRoute(_HttpRouteType.POST, endpoint.path, func_info, False)
    self._route_list.append(route)
    _LOG.info("add POST handler %s://%s:%d%s", "http", self._host, self._port, endpoint.path)

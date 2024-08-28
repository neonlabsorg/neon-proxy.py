from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Callable, Awaitable, Union

import robyn.robyn as _rb
import robyn.router as _rt
import robyn.status_codes as _st
from typing_extensions import Self

from .errors import HttpRouteError
from .utils import HttpMethod, HttpURL, HttpStrOrURL, HttpRequestCtx
from ..config.config import Config
from ..config.utils import LogMsgFilter, hide_sensitive_info
from ..utils.cached import cached_property, cached_method

_LOG = logging.getLogger(__name__)

_HttpRoute = _rt.Route
_HttpFunctionInfo = _rt.FunctionInfo
_HttpRouteType = _rb.HttpMethod
_RobynServer = _rb.Server
_http_get_version = _rb.get_version

HttpHolder = _rb.SocketHeld
HttpRequest = _rb.Request
HttpResp = _rb.Response
HttpHeaderDict = _rb.Headers


@dataclass(frozen=True)
class HttpSocket:
    host: str
    port: int

    @cached_property
    def holder(self) -> HttpHolder:
        return HttpHolder(self.host, self.port)

    @cached_method
    def to_string(self) -> str:
        return f"{'http'}://{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class HttpServer(abc.ABC):
    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(self._cfg)

        self._wrk_cnt = 1
        self._is_started = False
        self._robyn_server: _RobynServer | None = None
        self._http_socket: HttpSocket | None = None

        self._req_hdr_dict = HttpHeaderDict({})
        self._resp_hdr_dict = HttpHeaderDict({})
        self._route_list: list[_HttpRoute] = list()

    def listen(self, host: str, port: int) -> Self:
        self._http_socket = HttpSocket(host, port)
        _ = self._http_socket.holder
        return self

    @property
    def host(self) -> str:
        return self._http_socket.host

    @property
    def port(self) -> int:
        return self._http_socket.port

    @abc.abstractmethod
    def _register_handler_list(self) -> None: ...

    async def _on_server_start(self) -> None: ...
    async def _on_server_stop(self) -> None: ...

    def set_worker_cnt(self, value: int) -> Self:
        self._wrk_cnt = value
        return self

    def add_post_route(self, endpoint: HttpStrOrURL, post_handler: HttpHandler) -> None:
        return _add_http_handler(self, _HttpRouteType.POST, endpoint, post_handler)

    def add_get_route(self, endpoint: HttpStrOrURL, get_handler: HttpHandler) -> None:
        return _add_http_handler(self, _HttpRouteType.GET, endpoint, get_handler)

    def start(self) -> None:
        assert self._http_socket is not None, "Listen Host:Port aren't defined"
        assert not self._is_started, "Server is already started"

        if not self._route_list:
            self._register_handler_list()
            assert self._route_list, "No route list?"

        # run Robyn HTTP server
        _LOG.info("start Robyn HTTP Server v%s at the %s", _http_get_version(), self._http_socket)

        self._is_started = True
        self._robyn_server = server = _RobynServer()

        server.add_startup_handler(_HttpFunctionInfo(_start_process_event(self), True, 0, {}, {}))
        server.add_shutdown_handler(_HttpFunctionInfo(_shutdown_process_event(self), True, 0, {}, {}))

        server.apply_request_headers(self._req_hdr_dict)
        server.apply_response_headers(self._resp_hdr_dict)

        for route in self._route_list:
            server.add_route(route.route_type, route.route, route.function, route.is_const)

        server.start(self._http_socket.holder.try_clone(), self._wrk_cnt)

    def stop(self) -> None:
        assert self._is_started
        del self._robyn_server
        self._robyn_server = None
        self._is_started = False

    @classmethod
    def _pack_json_resp(cls, ctx: HttpRequestCtx, body_json: str) -> HttpResp:
        return HttpResp(
            status_code=_st.HTTP_200_OK,
            description=body_json,
            headers=cls._create_header_dict(ctx, "application/json"),
        )

    @classmethod
    def _pack_text_resp(cls, ctx: HttpRequestCtx, body_str: str | bytes, content_type: str = "text/plain") -> HttpResp:
        return HttpResp(
            status_code=_st.HTTP_200_OK,
            description=body_str,
            headers=cls._create_header_dict(ctx, content_type),
        )

    def _pack_error_resp(self, ctx: HttpRequestCtx, exc: BaseException) -> HttpResp:
        msg = dict(
            message="error on {Path} from {IP}",
            Path=ctx.path,
            IP=ctx.ip_addr,
        )
        _LOG.error(msg, exc_info=exc)

        return HttpResp(
            status_code=_st.HTTP_500_INTERNAL_SERVER_ERROR,
            description=hide_sensitive_info(self._msg_filter, str(exc)),
            headers=self._create_header_dict(ctx),
        )

    @classmethod
    def _pack_bad_route_resp(cls, ctx: HttpRequestCtx) -> HttpResp:
        return HttpResp(
            status_code=_st.HTTP_404_NOT_FOUND,
            description="The requested URL was not found on this server.",
            headers=cls._create_header_dict(ctx),
        )

    @classmethod
    def _create_header_dict(cls, ctx: HttpRequestCtx, content_type: str = "text/plain") -> HttpHeaderDict:
        hdr_dict = {
            "Content-Type": f"{content_type}; charset=utf-8",
            "X-Process-Time": ctx.process_time_msec,
            "Allow": "POST, GET",
        }
        return HttpHeaderDict(hdr_dict)


HttpHandler = Union[
    Callable[[HttpServer, HttpRequestCtx], Awaitable[HttpResp]],
    Callable[[HttpServer, HttpRequestCtx], HttpResp],
    Callable[[HttpRequestCtx], Awaitable[HttpResp]],
    Callable[[HttpRequestCtx], HttpResp],
]


def _start_process_event(self: HttpServer) -> Callable:
    async def _wrapper() -> None:
        await self._on_server_start()
        _LOG.info("HttpWorker is started")

    return _wrapper


def _shutdown_process_event(self: HttpServer) -> Callable:
    async def _wrapper() -> None:
        await self._on_server_stop()
        _LOG.info("HttpWorker is stopped")

    return _wrapper


def _add_http_handler(
    self: HttpServer,
    route_type: _HttpRouteType,
    base_path: HttpStrOrURL,
    handler: HttpHandler,
) -> None:
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

    route = _HttpRoute(route_type, endpoint.path, func_info, False)
    self._route_list.append(route)

    def _route_name() -> str:
        if route_type == _HttpRouteType.GET:
            return "GET"
        elif route_type == _HttpRouteType.POST:
            return "POST"
        return "UNKNOWN"

    _LOG.info("add %s handler %s%s", _route_name(), self._http_socket, endpoint.path)

from __future__ import annotations

import logging
import typing
from typing import Awaitable, Callable, Union, Sequence

from .api import (
    AppRequest,
    AppResp,
    AppErrorModel,
)
from .errors import (
    PydanticValidationError,
    AppRequestValidationError,
    BaseAppDataError,
)
from .utils import AppDataMethod
from ..config.utils import hide_sensitive_info
from ..http.api_sever import BaseApiServer, BaseApi
from ..http.errors import BaseHttpError, HttpRouteError
from ..http.server import HttpHeaderDict, HttpResp
from ..http.utils import HttpRequestIdField, HttpURL, HttpRequestCtx
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class AppDataApi(BaseApi):
    @classmethod
    def method(
        cls,
        handler: AppDataHandler | None = None,
        *,
        name: str | Sequence[str] | None = None,
    ) -> Callable:
        def _parser(_handler: AppDataHandler) -> AppDataHandler:
            name_list = [name] if (not name) or isinstance(name, str) else name
            for method_name in name_list:
                method = AppDataMethod.from_handler(_handler, method_name, allow_request_ctx=True)
                cls.__method_list__.append(method)
            return _handler

        if handler:
            return _parser(handler)

        return _parser


class AppDataServer(BaseApiServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._req_hdr_dict = HttpHeaderDict({"Content-Type": "application/json; charset=utf-8"})

    def _register_handler_list(self) -> None:
        self._validate_unique_method_path()

        # Register methods
        for base_url, api_list in self._url_api_dict.items():
            for api in api_list:
                api = typing.cast(AppDataApi, api)
                for method in api.__method_list__:
                    method_path = base_url.join(HttpURL(method.name))
                    _register_data_handler(api, method_path, method)


AppDataHandler = Union[
    Callable[[AppDataServer, HttpRequestIdField, AppRequest], Awaitable[BaseModel]],
    Callable[[AppDataServer, HttpRequestIdField, AppRequest], BaseModel],
    Callable[[HttpRequestIdField, AppRequest], Awaitable[BaseModel]],
    Callable[[HttpRequestIdField, AppRequest], BaseModel],
]


def _register_data_handler(api: AppDataApi, method_path: HttpURL, method: AppDataMethod) -> None:
    _RequestType = method.RequestType
    _RespType = method.RespType

    server = typing.cast(AppDataServer, api.server)

    def _sync_wrapper(ctx: HttpRequestCtx) -> HttpResp:
        # parse input and validate it
        resp, args = _parse_request(api, method, ctx)
        if resp is not None:
            return resp

        try:
            # call handler
            resp = method.handler(*args)
            return _pack_json_resp(server, method, ctx, resp)
        except HttpRouteError:
            raise
        except BaseException as exc:
            return _pack_error_resp(server, ctx, exc)

    async def _async_wrapper(ctx: HttpRequestCtx) -> HttpResp:
        # parse input and validate it
        resp, args = _parse_request(api, method, ctx)
        if resp is not None:
            return resp

        try:
            # call handler
            resp = await method.handler(*args)
            return _pack_json_resp(server, method, ctx, resp)
        except HttpRouteError:
            raise
        except BaseException as exc:
            return _pack_error_resp(server, ctx, exc)

    _wrapper = _async_wrapper if method.is_async_def else _sync_wrapper
    server.add_post_route(method_path, _wrapper)


def _parse_request(
    api: AppDataApi,
    method: AppDataMethod,
    ctx: HttpRequestCtx,
) -> tuple[HttpResp | None, tuple]:
    try:
        request_model = AppRequest.from_json(ctx.body)
        ctx.set_req_id(request_model.id)

        arg_list = list()
        if method.has_self:
            arg_list.append(api)
        if method.has_ctx:
            arg_list.append(ctx)
        if method.RequestType is not None:
            arg_list.append(method.RequestType.from_dict(request_model.data))

        return None, tuple(arg_list)

    except HttpRouteError:
        raise

    except BaseException as exc:
        if isinstance(exc, PydanticValidationError):
            exc = AppRequestValidationError(exc)
        server = typing.cast(AppDataServer, api.server)
        return _pack_error_resp(server, ctx, exc), tuple()


def _pack_json_resp(
    self: AppDataServer, method: AppDataMethod, ctx: HttpRequestCtx, resp: BaseModel
) -> HttpResp:
    assert isinstance(resp, method.RespType), "AppDataHandler returned invalid response"
    body_model = AppResp(id=ctx.req_id, result=resp.to_dict())
    return self._pack_json_resp(ctx, body_model.to_json())


def _pack_error_resp(self: AppDataServer, ctx: HttpRequestCtx, exc: BaseException) -> HttpResp:
    if not isinstance(exc, BaseHttpError):
        return self._pack_error_resp(ctx, exc)

    msg = dict(
        message="error on {Path} from {IP}: {Error}",
        Path=ctx.path,
        IP=ctx.ip_addr,
        Error=str(exc),
    )
    _LOG.debug(msg, extra=self._msg_filter)

    error_list = hide_sensitive_info(self._msg_filter, list(exc.error_list))
    msg = hide_sensitive_info(self._msg_filter, exc.message)
    data = dict(errors=error_list) if len(error_list) > 0 else None
    code = exc.code if isinstance(exc, BaseAppDataError) else -1
    error_model = AppErrorModel(code=code, message=msg, data=data)

    body_model = AppResp(id=ctx.req_id, error=error_model)
    return self._pack_json_resp(ctx, body_model.to_json())

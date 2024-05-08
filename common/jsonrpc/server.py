from __future__ import annotations

import logging
import time
import typing
from typing import Awaitable, Callable, Optional, Any, Sequence, Union

from .api import (
    JsonRpcRequest,
    JsonRpcListRequest,
    JsonRpcErrorModel,
    JsonRpcResp,
    JsonRpcListResp,
)
from .errors import (
    BaseJsonRpcError,
    PydanticValidationError,
    ParseRequestError,
    MethodNotFoundError,
    InvalidParamError,
    InternalJsonRpcError,
)
from .utils import JsonRpcMethod
from ..config.utils import hide_sensitive_info
from ..http.api_sever import BaseApiServer, BaseApi
from ..http.errors import HttpRouteError
from ..http.server import HttpResp, HttpHeaderDict
from ..http.utils import HttpURL, HttpRequestCtx
from ..utils.json_logger import log_msg

_LOG = logging.getLogger(__name__)


class JsonRpcApi(BaseApi):
    @classmethod
    def method(
        cls,
        handler: Optional[JsonRpcHandler] = None,
        *,
        name: str | Sequence[str] | None = None,
        predefined_params: bool = False,
    ) -> Callable:
        def _parser(_handler: JsonRpcHandler) -> JsonRpcHandler:
            name_list = [name] if (not name) or isinstance(name, str) else name
            for method_name in name_list:
                method = JsonRpcMethod.from_handler(_handler, method_name, predefined_params, allow_request_ctx=True)
                cls.__method_list__.append(method)
            return _handler

        if handler:
            return _parser(handler)
        return _parser


class JsonRpcServer(BaseApiServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._virtual_method_name = True
        self._req_hdr_dict = HttpHeaderDict({"Content-Type": "application/json"})

    def _register_handler_list(self) -> None:
        self._validate_unique_method_path()

        # Register methods
        for base_url, api_list in self._url_api_dict.items():
            method_dict = {
                method.name: (typing.cast(JsonRpcApi, api), method)
                for api in api_list
                for method in api.__method_list__
            }
            _register_jsonrpc_route(self, base_url, method_dict)

    async def on_request_list(self, ctx: HttpRequestCtx, request: JsonRpcListRequest) -> None: ...
    def on_response_list(self, ctx: HttpRequestCtx, resp: JsonRpcListResp) -> None: ...
    def on_bad_request(self, ctx: HttpRequestCtx) -> None: ...

    @classmethod
    async def handle_request(cls, ctx: HttpRequestCtx, req: JsonRpcRequest, handler: Callable) -> JsonRpcResp:
        return await handler(ctx, req)


JsonRpcHandler = Union[
    Callable[[JsonRpcServer, ...], Awaitable],
    Callable[[JsonRpcServer, ...], Any],
]


def _register_jsonrpc_route(
    self: JsonRpcServer, base_url: HttpURL, method_dict: dict[str, tuple[JsonRpcApi, JsonRpcMethod]]
) -> None:
    async def _wrapper(ctx: HttpRequestCtx) -> HttpResp:
        resp_list = JsonRpcListResp()
        try:
            req_list = _unpack_req_list(ctx)
            if req_list.is_list and len(req_list) > 1:
                await self.on_request_list(ctx, req_list)

        except BaseException as exc:
            self.on_bad_request(ctx)
            resp = _create_error_resp(self, ctx, exc)
            resp_list.append(resp)

        else:
            # the start time for the first request includes the time of list parsing
            start_time_nsec = ctx.start_time_nsec
            for req in req_list:
                req_ctx = HttpRequestCtx.from_raw(
                    ctx.path,
                    ctx=ctx,
                    sub_path=req.method,
                    req_id=req.id,
                    start_time_nsec=start_time_nsec,
                )
                resp = await self.handle_request(req_ctx, req, _handle_request)
                resp_list.append(resp)

                # flash start time for the next request
                start_time_nsec = time.monotonic_ns()

            if req_list.is_list:
                resp_list.convert_to_list()
                if len(resp_list) > 1:
                    self.on_response_list(ctx, resp_list)

        return self._pack_json_resp(ctx, resp_list.to_json())

    async def _handle_request(ctx: HttpRequestCtx, req: JsonRpcRequest) -> JsonRpcResp:
        api, method = method_dict.get(req.method, (None, None))
        if api is None:
            return _create_error_resp(self, ctx, MethodNotFoundError(req.method))

        if method.is_async_def:
            return await _async_method_handler(api, method, ctx, req)
        return _sync_method_handler(api, method, ctx, req)

    self.add_post_route(base_url, _wrapper)


def _unpack_req_list(ctx: HttpRequestCtx) -> JsonRpcListRequest:
    try:
        req_list = JsonRpcListRequest.from_json(ctx.body)
    except BaseException as exc:
        raise ParseRequestError(exc)

    if req_list.is_empty:
        raise ParseRequestError(None, error_list="Request cannot be an empty.")

    return req_list


async def _async_method_handler(
    self: JsonRpcApi,
    method: JsonRpcMethod,
    ctx: HttpRequestCtx,
    req: JsonRpcRequest,
) -> JsonRpcResp:
    try:
        # convert input params from jsonrpc request to method params
        kwargs = _params_to_kwargs(self, method, ctx, req.params)

        # run handler
        value = await method.handler(**kwargs)

        # pack response
        return _create_jsonrpc_resp(method, ctx, value)

    except HttpRouteError:
        raise

    except BaseException as exc:
        return _create_error_resp(self.server, ctx, exc)


def _sync_method_handler(
    self: JsonRpcApi,
    method: JsonRpcMethod,
    ctx: HttpRequestCtx,
    req: JsonRpcRequest,
) -> JsonRpcResp:
    try:
        # convert input params from jsonrpc request to method input params
        kwargs = _params_to_kwargs(self, method, ctx, req.params)

        # run handler
        value = method.handler(**kwargs)
        assert value is not None

        # pack response
        return _create_jsonrpc_resp(method, ctx, value)

    except HttpRouteError:
        raise

    except BaseException as exc:
        return _create_error_resp(self.server, ctx, exc)


def _params_to_kwargs(
    self: JsonRpcApi, method: JsonRpcMethod, ctx: HttpRequestCtx, req_value_list: Sequence
) -> dict[str, Any]:
    got_len = len(req_value_list)
    exp_len = len(method.param_name_list)
    if got_len > exp_len:
        raise InvalidParamError(
            None,
            error_list=f"Method {method.name} expect {exp_len} parameters, got {got_len}.",
        )

    # attach values to the param names
    req_value_dict = {param_name: value for param_name, value in zip(method.param_name_list, req_value_list)}

    try:
        # validate input parameters with pydantic tools
        req = method.RequestValidator.from_dict(req_value_dict)
    except PydanticValidationError as exc:
        raise InvalidParamError(exc)

    if method.predefined_params:
        param_value_dict = dict(params=req)
    else:
        # extract named params
        param_value_dict = {param_name: getattr(req, param_name) for param_name in method.param_name_list}

    if method.has_self:
        param_value_dict["self"] = self
    if method.has_ctx:
        param_value_dict["ctx"] = ctx
    return param_value_dict


def _create_jsonrpc_resp(method: JsonRpcMethod, ctx: HttpRequestCtx, value) -> JsonRpcResp:
    if method.ReturnValidator:
        resp = method.ReturnValidator.from_dict(dict(result=value))
        result = resp.to_dict()["result"]
    else:
        result = value.to_dict()
    return JsonRpcResp(id=ctx.req_id, jsonrpc="2.0", result=result)


def _create_error_resp(self: BaseApiServer, ctx: HttpRequestCtx, exc: BaseException) -> JsonRpcResp:
    extra = self._msg_filter
    if not isinstance(exc, BaseJsonRpcError):
        _LOG.error(
            log_msg("unexpected error on {Path} from {IP}", Path=ctx.path, IP=ctx.ip_addr),
            exc_info=exc,
            extra=extra,
        )
        exc = InternalJsonRpcError(exc)
    else:
        _LOG.debug(
            log_msg("error on {Path} from {IP}: {Error}", Path=ctx.path, IP=ctx.ip_addr, Error=str(exc)),
            extra=extra,
        )

    msg = hide_sensitive_info(self._msg_filter, exc.message)
    error_list = hide_sensitive_info(self._msg_filter, list(exc.error_list))
    data = dict(errors=error_list) if error_list else exc.data

    error_info = JsonRpcErrorModel(code=exc.code, message=msg, data=data)
    return JsonRpcResp(id=ctx.req_id, jsonrpc="2.0", error=error_info)

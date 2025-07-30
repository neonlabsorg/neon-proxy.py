from __future__ import annotations
import asyncio
import itertools
import logging
from typing import Callable, Awaitable, Any, Final, Iterator, Sequence, Union, AsyncGenerator, ClassVar

from .api import (
    JsonRpcRequest,
    JsonRpcListRequest,
    JsonRpcResp,
    JsonRpcListResp,
)
from .errors import (
    BaseJsonRpcError,
    ParseRespError,
    JsonRpcErrorDict,
)
from .utils import JsonRpcMethod
from ..config.config import Config
from ..config.constants import ONE_BLOCK_SEC
from ..http.client import HttpClient
from ..http.errors import PydanticValidationError
from ..stat.client_rpc import RpcClientRequest
from ..utils.pydantic import BaseModel
from proxy.stat.client import StatClient

_LOG = logging.getLogger(__name__)

class JsonRpcClient(HttpClient):
    name: ClassVar[str] = "JsonRpcClient"
    _wait_sec: Final[float] = max(ONE_BLOCK_SEC / 5, 0.05)

    def __init__(self, cfg: Config, stat_client: StatClient | None = None) -> None:
        super().__init__(cfg)
        self._id = itertools.count()
        self._stat_client: StatClient | None = stat_client

    @staticmethod
    def method(
        handler: JsonRpcClientSender | None = None,
        *,
        name: str = None,
        predefined_params: bool = False,
        is_batch: bool = False,
    ) -> Callable:
        def _single_registrator(_handler: JsonRpcClientSender) -> JsonRpcClientSender:
            return _register_single_sender(_handler, name, predefined_params)

        def _batch_registrator(_handler: JsonRpcClientSender) -> JsonRpcClientSender:
            return _register_batch_sender(_handler, name, predefined_params)

        if handler:
            if is_batch:
                return _batch_registrator(handler)
            return _single_registrator(handler)

        if is_batch:
            return _batch_registrator
        return _single_registrator

    @staticmethod
    def _rpc_error_handler(method: str, code: int, message: str, error_list: Sequence[str] | None) -> str | None:
        return "RPC Error: %d (%s); Error list: %s" % (code, message, ', '.join(error_list))

JsonRpcClientSender = Union[
    Callable[[JsonRpcClient, ...], Awaitable[JsonRpcResp]],
    Callable[[JsonRpcClient, ...], Awaitable[Iterator[JsonRpcResp]]],
]


def _register_single_sender(handler: JsonRpcClientSender, name: str, predefined_params: bool) -> Callable:
    method = JsonRpcMethod.from_handler(handler, name, predefined_params, is_batch=False)
    assert method.is_async_def, "JsonRpcClient support only async methods"
    assert method.has_self, "JsonRpcClient support only object methods"

    async def _callback(self: JsonRpcClient, *args, **kwargs) -> method.ReturnType:
        args = list(args)

        param_value_list = (
            _predefined_to_params(method, args, **kwargs)
            if method.predefined_params
            else _kwargs_to_params(method, args, **kwargs)
        )
        req_id = str(next(self._id))
        req_json = JsonRpcRequest(
            id=req_id,
            jsonrpc="2.0",
            method=method.name,
            params=param_value_list,
        ).to_json()

        req = RpcClientRequest.from_raw(
            data=req_json,
            stat_client=self._stat_client,
            stat_name=self.name,
            method=method.name,
        )
        with req:
            for retry in itertools.count():
                req.start_timer()

                if retry > 0:
                    _LOG.debug("attempt %d to repeat %s...", retry + 1, method.name)

                resp_json = await self._send_client_request(req)
                try:
                    resp_model = JsonRpcResp.from_json(resp_json)
                except PydanticValidationError as exc:
                    req.commit_stat(error_message=str(exc))
                    await asyncio.sleep(self._wait_sec)
                    continue
                    #raise ParseRespError(exc)

                if req_id != resp_model.id:
                    req.commit_stat(error_message="Response id mismatch")
                    await asyncio.sleep(self._wait_sec)
                    continue
                    #raise ParseRespError(None, error_list=("Response id mismatch",))

                try:
                    return _extract_return(self, method, req, resp_model)
                except (PydanticValidationError, BaseJsonRpcError) as exc:
                    await asyncio.sleep(self._wait_sec)
                    continue

        assert False, "unreached code"

    return _callback


def _kwargs_to_params(method: JsonRpcMethod, args: list[Any], **kwargs) -> list:
    param_name_list = method.param_name_list

    for param_name, param_value in zip(param_name_list, args):
        assert param_name not in kwargs, f"Duplicate value for {param_name}"
        kwargs[param_name] = param_value
    assert len(kwargs) <= len(param_name_list)
    params_model = method.RequestValidator(**kwargs)

    param_value_dict = params_model.to_dict()
    return [param_value_dict[param_name] for param_name in param_name_list]


def _predefined_to_params(method: JsonRpcMethod, args: list, **kwargs) -> list:
    if args:
        assert len(args) == 1, f"Surplus positional arguments {len(args) - 1}"
        assert not len(kwargs), f"Surplus named arguments {len(kwargs) - 1}"
        params_model = args[0]
    else:
        assert len(kwargs) == 1, f"Surplus named arguments {len(kwargs) - 1}"
        params_model: method.RequestValidator | None = kwargs.get("params", None)

    return _params_model_to_params(method, params_model)


def _register_batch_sender(handler: JsonRpcClientSender, name: str, predefined_params: bool) -> Callable:
    method = JsonRpcMethod.from_handler(handler, name, predefined_params, is_batch=True)
    assert method.is_async_def, "JsonRpcClient supports only async methods"
    assert method.has_self, "JsonRpcClient supports only object methods"
    assert method.RequestList is not None, "JsonRpcClient input batch list isn't defined"

    async def _callback(self: JsonRpcClient, params_list: method.RequestList) -> AsyncGenerator[Any, None]:
        req_list = JsonRpcListRequest()
        for params in params_list:
            req_id = str(next(self._id))
            req_model = JsonRpcRequest(
                id=req_id,
                jsonrpc="2.0",
                method=method.name,
                params=_params_model_to_params(method, params),
            )
            req_list.append(req_model)
        req_json = req_list.to_json()

        req = RpcClientRequest.from_raw(
            data=req_json,
            stat_client=self._stat_client,
            stat_name=self.name,
            method=method.name,
        )
        with req:
            for retry in itertools.count():
                req.start_timer()

                if retry > 0:
                    _LOG.debug("attempt %d to repeat %s...", retry + 1, method.name)

                resp_json = await self._send_client_request(req)
                try:
                    resp_list = JsonRpcListResp.from_json(resp_json)
                except PydanticValidationError as exc:
                    req.commit_stat(error_message=str(exc))
                    await asyncio.sleep(self._wait_sec)
                    continue
                    #raise ParseRespError(exc)

                if len(params_list) != len(resp_list):
                    req.commit_stat(error_message=f"Wrong number of answers: {len(params_list)} != {len(resp_list)}")
                    await asyncio.sleep(self._wait_sec)
                    continue
                    #raise ParseRespError(None, error_list=(f"Wrong number of answers: {len(params_list)} != {len(resp_list)}",))

                try:
                    for req_model, resp in zip(req_list, resp_list):
                        if req_model.id != resp.id:
                            raise ParseRespError(None, error_list=f"Response id mismatch: {req_model.id} != {resp.id}")
                        yield _extract_return(self, method, req, resp)
                except (PydanticValidationError, BaseJsonRpcError) as exc:
                    await asyncio.sleep(self._wait_sec)
                    continue

        assert False, "unreached code"

    return _callback


def _params_model_to_params(method: JsonRpcMethod, params_model: BaseModel):
    assert isinstance(params_model, method.RequestValidator), f"Bad type of params {type(params_model).__name__}"
    param_value_dict = params_model.to_dict()
    return [param_value_dict[param_name] for param_name in method.param_name_list]


def _extract_return(self: JsonRpcClient, method: JsonRpcMethod, req: RpcClientRequest, resp: JsonRpcResp) -> Any:
    if resp.is_error:
        error = resp.error
        error_list: list[str] | None = None
        if error.data is not None:
            error_list = error.data.get("errors", None)

        err_msg = self._rpc_error_handler(method.name, error.code, error.message, error_list)
        req.commit_stat(error_message=err_msg)
        _LOG.error(err_msg)

        _JsonRpcError = JsonRpcErrorDict.get(error.code, BaseJsonRpcError)
        raise _JsonRpcError(
            message=error.message,
            error_list=error_list,
            code=error.code,
        )

    try:
        if method.ReturnValidator:
            return_model = method.ReturnValidator.from_dict(dict(result=resp.result))
            result = getattr(return_model, "result")
        else:
            result = method.ReturnType.from_dict(resp.result)  # noqa

        req.commit_stat()
        return result

    except PydanticValidationError as exc:
        req.commit_stat(error_message=str(exc))
        raise ParseRespError(exc)

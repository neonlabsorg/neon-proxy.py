from __future__ import annotations

from types import NoneType
from typing import Callable, Awaitable, Union

from .errors import BadRespError
from .utils import SimpleAppDataMethod
from ..http.client import HttpClient
from ..http.utils import HttpURL
from ..utils.pydantic import BaseModel


class SimpleAppDataClient(HttpClient):
    @classmethod
    def method(
        cls,
        handler: SimpleAppDataClientSender | None = None,
        *,
        name: str = None,
    ) -> Callable:
        def _registrator(_handler: SimpleAppDataClientSender) -> SimpleAppDataClientSender:
            return cls._register_data_sender(_handler, name)

        if handler:
            return _registrator(handler)

        return _registrator

    @classmethod
    def _register_data_sender(cls, handler: SimpleAppDataClientSender, name: str) -> Callable:
        method = SimpleAppDataMethod.from_handler(handler, name)

        assert method.is_async_def, "SimpleAppDataClient support only async methods"
        assert method.has_self, "SimpleAppDataClient support only object methods"

        _RequestType = method.RequestType
        _RespType = method.RespType
        method_path = HttpURL(method.name)

        def _req_to_json(data: _RequestType) -> str:
            assert isinstance(
                data, _RequestType
            ), f"Wrong type of the request {type(data).__name__} != {_RequestType.__name__}"
            return data.to_json()

        async def _null_wrapper(self: SimpleAppDataClient) -> _RespType:
            resp_json = await self._send_post_request("", path=method_path)
            return _parse_resp(resp_json)

        async def _null_wrapper_no_return(self: SimpleAppDataClient) -> None:
            if resp := await self._send_post_request("", path=method_path):
                raise BadRespError(error_list=f"The server returned a data: {resp}")

        async def _wrapper(self: SimpleAppDataClient, data: _RequestType) -> _RespType:
            req_json = _req_to_json(data)
            resp_json = await self._send_post_request(req_json, path=method_path)
            return _parse_resp(resp_json)

        async def _wrapper_no_return(self: SimpleAppDataClient, data: _RequestType) -> None:
            req_json = _req_to_json(data)
            if resp := await self._send_post_request(req_json, path=method_path):
                raise BadRespError(error_list=f"The server returned a data: {resp}")

        def _parse_resp(resp_json: str) -> _RespType:
            try:
                return _RespType.from_json(resp_json)
            except BaseException as exc:
                raise BadRespError(exc)

        if issubclass(_RequestType, NoneType):
            if issubclass(_RespType, NoneType):
                return _null_wrapper_no_return
            return _null_wrapper
        elif issubclass(_RespType, NoneType):
            return _wrapper_no_return
        return _wrapper


SimpleAppDataClientSender = Union[
    Callable[[SimpleAppDataClient, BaseModel], Awaitable[BaseModel]],
    Callable[[SimpleAppDataClient], Awaitable[BaseModel]],
]

from __future__ import annotations

import itertools
from types import NoneType
from typing import Callable, Union, Awaitable

from .api import AppRequest, AppResp
from .errors import BaseAppDataError, BadRespError, PydanticValidationError
from .utils import AppDataMethod
from ..http.client import HttpClient
from ..http.utils import HttpURL
from ..utils.pydantic import BaseModel


class AppDataClient(HttpClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._req_id = itertools.count()

    @classmethod
    def method(
        cls,
        handler: AppDataClientSender | None = None,
        *,
        name: str = None,
    ) -> Callable:
        def _registrator(_handler: AppDataClientSender) -> AppDataClientSender:
            return cls._register_data_sender(_handler, name)

        if handler:
            return _registrator(handler)

        return _registrator

    @classmethod
    def _register_data_sender(cls, handler: AppDataClientSender, name: str) -> Callable:
        method = AppDataMethod.from_handler(handler, name)
        assert method.is_async_def, "AppDataClient support only async methods"
        assert method.has_self, "AppDataClient support only object methods"

        _RequestType = method.RequestType
        _RespType = method.RespType
        method_path = HttpURL(method.name)

        async def _null_wrapper(self: AppDataClient) -> _RespType:
            resp = await _send_request(self, None)
            return _parse_resp(resp)

        async def _null_wrapper_no_return(self: AppDataClient) -> None:
            if resp := await _send_request(self, None):
                raise BadRespError(error_list=f"The server returned a data: {resp}")

        def _req_to_dict(data: _RequestType) -> dict:
            assert isinstance(
                data, _RequestType
            ), f"Wrong type of the request {type(data).__name__} != {_RequestType.__name__}"
            return data.to_dict()

        async def _wrapper(self: AppDataClient, data: _RequestType) -> _RespType:
            resp = await _send_request(self, _req_to_dict(data))
            return _parse_resp(resp)

        async def _wrapper_no_return(self: AppDataClient, data: _RequestType) -> None:
            if resp := await _send_request(self, _req_to_dict(data)):
                raise BadRespError(error_list=f"The server returned a data: {resp}")

        async def _send_request(self: AppDataClient, data: dict | None) -> dict | None:
            req_id = str(next(self._req_id))
            req_data = AppRequest(id=req_id, data=data).to_json()

            resp_data = await self._send_raw_data_request(req_data, path=method_path)
            resp = AppResp.from_json(resp_data)
            if resp.id != req_id:
                raise BadRespError(error_list=f"Bad ID in the response {resp.id} != {req_id}")

            if resp.is_error():
                error = resp.error
                error_list = error.data.get("errors", tuple())
                raise BaseAppDataError(error.message, code=error.code, error_list=error_list)
            return resp.result

        def _parse_resp(resp: dict) -> _RespType:
            try:
                return _RespType.from_dict(resp)
            except PydanticValidationError as exc:
                raise BadRespError(exc)

        if issubclass(_RequestType, NoneType):
            if issubclass(_RespType, NoneType):
                return _null_wrapper_no_return
            return _null_wrapper
        elif issubclass(_RespType, NoneType):
            return _wrapper_no_return
        return _wrapper


AppDataClientSender = Union[
    Callable[[AppDataClient, BaseModel], Awaitable[BaseModel]],
    Callable[[AppDataClient], Awaitable[BaseModel]],
]

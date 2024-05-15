from __future__ import annotations

import itertools
from typing import Callable

from .api import AppRequest, AppResp
from .errors import BaseAppDataError, BadRespError, PydanticValidationError
from .utils import AppDataMethod
from ..http.utils import HttpURL
from ..simple_app_data.client import SimpleAppDataClient, SimpleAppDataClientSender


class AppDataClient(SimpleAppDataClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._req_id = itertools.count()

    @classmethod
    def _register_data_sender(cls, handler: SimpleAppDataClientSender, name: str, reraise_50x: bool) -> Callable:
        method = AppDataMethod.from_handler(handler, name)
        assert method.is_async_def, "AppDataClient support only async methods"
        assert method.has_self, "AppDataClient support only object methods"

        _RequestType = method.RequestType
        _RespType = method.RespType
        method_path = HttpURL(method.name)

        async def _null_wrapper(self: AppDataClient) -> _RespType:
            return await _send_request(self, None)

        async def _wrapper(self: AppDataClient, data: _RequestType) -> _RespType:
            assert isinstance(
                data, _RequestType
            ), f"Wrong type of the request {type(data).__name__} != {_RequestType.__name__}"
            data = data.to_dict()
            return await _send_request(self, data)

        async def _send_request(self: AppDataClient, data: dict | None) -> _RespType:
            req_id = str(next(self._req_id))
            req_data = AppRequest(id=req_id, data=data).to_json()

            resp_data = await self._send_post_request(req_data, path=method_path, reraise_50x=reraise_50x)
            resp = AppResp.from_json(resp_data)
            if resp.id != req_id:
                raise BadRespError(error_list=f"Bad ID in the response {resp.id} != {req_id}")

            if resp.is_error():
                error = resp.error
                error_list = error.data.get("errors", tuple())
                raise BaseAppDataError(error.message, code=error.code, error_list=error_list)

            try:
                return _RespType.from_dict(resp.result)
            except PydanticValidationError as exc:
                raise BadRespError(exc)

        if not _RequestType:
            return _null_wrapper
        return _wrapper


AppDataClientSender = SimpleAppDataClientSender

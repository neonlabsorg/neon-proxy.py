from __future__ import annotations

import asyncio
import unittest
from typing import AsyncIterator

from pydantic import StrictInt, StrictStr, Field

from common.config.config import Config
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import JsonRpcListMixin
from common.jsonrpc.client import JsonRpcClient
from common.jsonrpc.errors import InvalidParamError
from common.jsonrpc.server import JsonRpcServer, JsonRpcApi
from common.utils.process_pool import ProcessPool
from common.utils.pydantic import BaseModel, RootModel

HOST = "127.0.0.1"
PORT = 10002
ENDPOINT = "/api/v1"


class Bar(BaseModel):
    value: StrictInt


class HelloResp(BaseModel):
    message: str
    value: int
    has_with: bool = True


class TestParams(BaseModel):
    value: int
    message: str


class TestParamsRoot(JsonRpcListMixin[TestParams], RootModel):
    root: list[TestParams] = Field(default_factory=list)


class TestApiServer(JsonRpcServer):
    class _ProcessPool(ProcessPool):
        def __init__(self, server: TestApiServer) -> None:
            super().__init__()
            self._server = server

        def _on_process_start(self, idx: int) -> None:
            self._server._on_process_start()

        def _on_process_stop(self) -> None:
            self._server._on_process_stop()
            self._server = None

    class TestApi(JsonRpcApi):
        def __init__(self) -> None:
            super().__init__()
            self._stop_task: asyncio.Task | None = None

        @JsonRpcApi.method(name="json_helloWorld")
        async def hello(self, name: StrictStr, value: Bar) -> HelloResp:
            return HelloResp(message=f"Hello {name}", value=value.value)

        @JsonRpcApi.method(name="json_tryDefault")
        def try_default(self, ctx: HttpRequestCtx, name: str, value: int = 10) -> HelloResp:
            return HelloResp(message=f"Hello {name} {ctx.request.method}", value=value)

        @JsonRpcApi.method(name="json_Params", predefined_params=True)
        def try_params(self, params: TestParams) -> HelloResp:
            return HelloResp(message=f"Hello {params.message}", value=params.value)

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)

        self.listen(host=HOST, port=PORT)

        test_api = self.TestApi()
        self.add_api(test_api, endpoint=ENDPOINT)

        self._process_pool = self._ProcessPool(self)

    def start(self) -> None:
        self._process_pool.start()

    def stop(self) -> None:
        self._process_pool.stop()

    def _on_process_start(self) -> None:
        super().start()

    def _on_process_stop(self) -> None:
        super().stop()


class ApiClient(JsonRpcClient):
    @JsonRpcClient.method(name="json_helloWorld")
    async def hello(self, name: StrictStr, value: Bar) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default(self, name: str) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default1(self, name: str, value: int = 15) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default2(self, name: str, value: int, value1: int) -> HelloResp: ...

    @JsonRpcClient.method(name="json_Params", predefined_params=True)
    async def try_params(self, params: TestParams) -> HelloResp: ...

    @JsonRpcClient.method(name="json_Params", predefined_params=True, is_batch=True)
    def try_params_batch(self, params_list: TestParamsRoot) -> AsyncIterator[HelloResp]: ...


class TestJsonRpcProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config = Config()
        self._api_server = TestApiServer(config)
        self._api_server.start()
        self._api_client = ApiClient(config).connect(host=HOST, port=PORT, path=ENDPOINT)
        self._api_client.set_timeout_sec(1).set_max_retry_cnt(3)

    async def asyncTearDown(self):
        await self._api_client.stop()
        self._api_server.stop()

    async def test_jsonrpc(self):
        res = await self._api_client.hello(name="John", value=Bar(value=12))
        self.assertEqual(res.value, 12)

        res = await self._api_client.try_default(name="John")
        self.assertEqual(res.value, 10)

        res = await self._api_client.try_default1(name="John", value=14)
        self.assertEqual(res.value, 14)

        res = await self._api_client.try_default1(name="John")
        self.assertEqual(res.value, 15)

        with self.assertRaisesRegex(
            InvalidParamError, "Invalid params. Method json_tryDefault expect 2 parameters, got 3."
        ):
            _ = await self._api_client.try_default2(name="John", value=12, value1=10)

        res = await self._api_client.try_params(TestParams(message="John", value=24))
        self.assertEqual(res.value, 24)

        params_list = TestParamsRoot(
            [
                TestParams(message="John", value=94),
                TestParams(message="Alfi", value=85),
                TestParams(message="Andy", value=76),
            ]
        )
        params_iter = iter(params_list)

        async for res in self._api_client.try_params_batch(params_list):
            params = next(params_iter)
            self.assertEqual(params.value, res.value)


if __name__ == "__main__":
    unittest.main()

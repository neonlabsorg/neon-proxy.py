from __future__ import annotations

import unittest
from multiprocessing import Process
from typing import AsyncIterator

from pydantic import StrictInt, StrictStr, Field
from singleton_decorator import singleton

from common.config.config import Config
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import JsonRpcListMixin
from common.jsonrpc.client import JsonRpcClient
from common.jsonrpc.errors import InvalidParamError
from common.jsonrpc.server import JsonRpcServer, JsonRpcApi
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
    class TestApi(JsonRpcApi):
        @JsonRpcApi.method(name="json_helloWorld")
        async def hello(self, name: StrictStr, value: Bar) -> HelloResp:
            return HelloResp(message=f"Hello {name}", value=value.value)

        @JsonRpcApi.method(name="json_tryDefault")
        def try_default(self, ctx: HttpRequestCtx, name: str, value: int = 10) -> HelloResp:
            return HelloResp(message=f"Hello {name} {ctx.request.method}", value=value)

        @JsonRpcApi.method(name="json_Params", predefined_params=True)
        def try_params(self, params: TestParams) -> HelloResp:
            return HelloResp(message=f"Hello {params.message}", value=params.value)

        @JsonRpcApi.method(name="json_stopServer")
        async def stop_server(self) -> str:
            self.server.stop()
            return "Server stopped"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)

        self.set_process_cnt(2)
        self.listen(host=HOST, port=PORT)

        test_api = self.TestApi()
        self.add_api(test_api, endpoint=ENDPOINT)


@singleton
class ServerProcess:
    def __init__(self, cfg: Config) -> None:
        self._process: Process | None = None
        self._server = TestApiServer(cfg)

    def start(self):
        self._process = Process(target=self._run)
        self._process.start()

    def stop(self):
        self._server.stop()
        self._process.kill()

    def _run(self):
        self._server.start()


class ApiClient(JsonRpcClient):
    @JsonRpcClient.method(name="json_helloWorld")
    async def hello(self, name: StrictStr, value: Bar) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default(self, name: str) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default1(self, name: str, value: int = 15) -> HelloResp: ...

    @JsonRpcClient.method(name="json_tryDefault")
    async def try_default2(self, name: str, value: int, value1: int) -> HelloResp: ...

    @JsonRpcClient.method(name="json_stopServer")
    async def stop_server(self) -> str: ...

    @JsonRpcClient.method(name="json_Params", predefined_params=True)
    async def try_params(self, params: TestParams) -> HelloResp: ...

    @JsonRpcClient.method(name="json_Params", predefined_params=True, is_batch=True)
    def try_params_batch(self, params_list: TestParamsRoot) -> AsyncIterator[HelloResp]: ...


class TestJsonRpcProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config = Config()
        self._server_process = ServerProcess(config)
        self._server_process.start()
        self._api_client = ApiClient(config).connect(host=HOST, port=PORT, path=ENDPOINT)
        self._api_client.set_timeout_sec(1).set_max_retry_cnt(3)

    async def asyncTearDown(self):
        await self._api_client.stop()
        self._server_process.stop()

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
            InvalidParamError, "invalid parameters. Method json_tryDefault expect 2 parameters, got 3."
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

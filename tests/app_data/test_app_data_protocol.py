from __future__ import annotations

import asyncio
import unittest
from multiprocessing import Process

from singleton_decorator import singleton

from common.app_data.client import AppDataClient
from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.http.utils import HttpRequestCtx
from common.utils.pydantic import BaseModel

HOST = "127.0.0.1"
PORT = 10001
ENDPOINT = "/api/v1/"


class Bar(BaseModel):
    value: int


class HelloRequest(BaseModel):
    name: str
    value: Bar


class HelloResp(BaseModel):
    message: str
    value: int
    has_with: bool = True


class StopServerResp(BaseModel):
    message: str


class TestApi(AppDataApi):
    @AppDataApi.method(name="helloWorld")
    def hello(self, ctx: HttpRequestCtx, request: HelloRequest) -> HelloResp:
        return HelloResp(message=f"Hello {request.name} {ctx.request.method}", value=request.value.value)

    @AppDataApi.method(name="asyncHelloWorld")
    async def async_hello(self, request: HelloRequest) -> HelloResp:
        await asyncio.sleep(0.001)
        return HelloResp(message=f"Hello {request.name}", value=request.value.value, has_with=False)

    @AppDataApi.method(name="stopServer")
    async def stop_server(self) -> StopServerResp:
        self.server.stop()
        return StopServerResp(message="Server is going to stop")


class TestApiServer(AppDataServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        test_api = TestApi()
        self.set_process_cnt(2)
        self.listen(host=HOST, port=PORT)
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


class ApiClient(AppDataClient):
    @AppDataClient.method(name="helloWorld")
    async def hello(self, request: HelloRequest) -> HelloResp: ...

    @AppDataClient.method(name="asyncHelloWorld")
    async def async_hello(self, request: HelloRequest) -> HelloResp: ...

    @AppDataClient.method(name="stopServer")
    async def stop_server(self) -> StopServerResp: ...


class TestAppDataProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config = Config()
        self._server_process = ServerProcess(config)
        self._server_process.start()
        self._api_client = ApiClient(config)
        self._api_client.connect(host=HOST, port=PORT, path=ENDPOINT).set_timeout_sec(1).set_max_retry_cnt(3)

    async def asyncTearDown(self):
        await self._api_client.stop()
        self._server_process.stop()

    async def test_app_data_server(self):
        req = HelloRequest(name="world", value=Bar(value=42))
        res = await self._api_client.hello(req)
        self.assertEqual(res.value, req.value.value)
        self.assertTrue(res.has_with)

        req = HelloRequest(name="bar", value=Bar(value=55))
        res = await self._api_client.async_hello(req)
        self.assertEqual(res.value, req.value.value)
        self.assertFalse(res.has_with)

        res = await self._api_client.stop_server()
        self.assertGreater(len(res.message), 0)


if __name__ == "__main__":
    unittest.main()

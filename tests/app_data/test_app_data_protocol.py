from __future__ import annotations

import asyncio
import unittest

from common.app_data.client import AppDataClient
from common.app_data.server import AppDataServer, AppDataApi
from common.config.config import Config
from common.http.utils import HttpRequestCtx
from common.utils.process_pool import ProcessPool
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
    def __init__(self) -> None:
        super().__init__()
        self._stop_task: asyncio.Task | None = None

    @AppDataApi.method(name="helloWorld")
    def hello(self, ctx: HttpRequestCtx, request: HelloRequest) -> HelloResp:
        return HelloResp(message=f"Hello {request.name} {ctx.request.method}", value=request.value.value)

    @AppDataApi.method(name="asyncHelloWorld")
    async def async_hello(self, request: HelloRequest) -> HelloResp:
        await asyncio.sleep(0.001)
        return HelloResp(message=f"Hello {request.name}", value=request.value.value, has_with=False)

    @AppDataApi.method(name="stopServer")
    async def stop_server(self) -> StopServerResp:
        async def _stop() -> None:
            await asyncio.sleep(0.1)
            self._server.stop()

        self._stop_task = asyncio.get_event_loop().create_task(_stop())
        return StopServerResp(message="Server is going to stop")


class TestApiServer(AppDataServer):
    class _ProcessPool(ProcessPool):
        def __init__(self, server: TestApiServer) -> None:
            super().__init__()
            self._server = server

        def _on_process_start(self, idx: int) -> None:
            self._server._on_process_start()

        def _on_process_stop(self) -> None:
            self._server._on_process_stop()
            self._server = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._process_pool = self._ProcessPool(self)
        test_api = TestApi()
        self.listen(host=HOST, port=PORT)
        self.add_api(test_api, endpoint=ENDPOINT)

    def start(self) -> None:
        self._process_pool.start()

    def stop(self) -> None:
        self._process_pool.stop()

    def _on_process_start(self) -> None:
        super().start()

    def _on_process_stop(self) -> None:
        super().stop()


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
        self._api_server = TestApiServer(config)
        self._api_server.start()
        self._api_client = ApiClient(config)
        self._api_client.connect(host=HOST, port=PORT, path=ENDPOINT).set_timeout_sec(1).set_max_retry_cnt(30)

    async def asyncTearDown(self):
        await self._api_client.stop()
        self._api_server.stop()

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

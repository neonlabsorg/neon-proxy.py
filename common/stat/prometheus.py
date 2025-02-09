from __future__ import annotations

from typing import Final

from .client_metric import MetricStatClient
from ..config.config import Config
from ..http.server import HttpServer, HttpResp
from ..http.utils import HttpRequestCtx


class PrometheusServer(HttpServer):
    def __init__(self, cfg: Config, metric_endpoint: str) -> None:
        super().__init__(cfg)
        self._metric_client = MetricStatClient(cfg, metric_endpoint)
        self.listen(host="0.0.0.0", port=cfg.stat_public_port)

    async def _on_server_start(self) -> None:
        await super()._on_server_start()
        await self._metric_client.start()

    async def _on_server_stop(self) -> None:
        await super()._on_server_stop()
        await self._metric_client.stop()

    def _register_handler_list(self) -> None:
        base_url: Final[str] = self._http_socket.to_string()
        metric_url: Final[str] = "/metrics"
        full_metric_url = base_url + metric_url

        health_url: Final[str] = "/health"
        full_health_url = base_url + health_url

        def _index(ctx: HttpRequestCtx) -> HttpResp:
            nonlocal full_metric_url
            nonlocal full_health_url
            return self._pack_text_resp(
                ctx,
                "<html><body>"
                f"<a href='{full_metric_url}'>metrics</a>"
                f"<a href='{full_health_url}'>health</a>"
                "</body></html>",
                "text/html",
            )

        def _robot_txt(ctx: HttpRequestCtx) -> HttpResp:
            return self._pack_text_resp(ctx, "User-agent: *\nDisallow: /\n")

        async def _metric(ctx: HttpRequestCtx) -> HttpResp:
            stat = await self._metric_client.get_metric_stat()
            return self._pack_text_resp(ctx, stat.data, "text/plain; version=0.0.4")

        async def _health(ctx: HttpRequestCtx) -> HttpResp:
            health = await self._metric_client.get_health_error_list()
            return self._pack_text_resp(ctx, health.data, "text/plain; version=0.0.4")

        self.add_get_route("/", _index)
        self.add_get_route("/robots.txt", _robot_txt)
        self.add_get_route(metric_url, _metric)
        self.add_get_route(health_url, _health)

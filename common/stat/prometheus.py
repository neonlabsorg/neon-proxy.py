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

        status_url: Final[str] = "/status"
        full_status_url = base_url + status_url

        healthz_url: Final[str] = "/healthz"
        full_healthz_url = base_url + healthz_url

        def _index(ctx: HttpRequestCtx) -> HttpResp:
            nonlocal full_metric_url
            nonlocal full_status_url
            nonlocal full_healthz_url
            return self._pack_text_resp(
                ctx,
                "<html><body>"
                "<h1>Prometheus Server</h1>"
                f"<p><a href='{full_metric_url}'>metrics</a></p>"
                f"<p><a href='{full_status_url}'>status</a></p>"
                f"<p><a href='{full_healthz_url}'>healthz</a><div></p>"
                "</body></html>",
                "text/html",
            )

        def _robot_txt(ctx: HttpRequestCtx) -> HttpResp:
            return self._pack_text_resp(ctx, "User-agent: *\nDisallow: /\n")

        async def _metric(ctx: HttpRequestCtx) -> HttpResp:
            stat = await self._metric_client.get_metric_stat()
            return self._pack_text_resp(ctx, stat.data, "text/plain; version=0.0.4")

        async def _status(ctx: HttpRequestCtx) -> HttpResp:
            status = await self._metric_client.get_health_error_list()
            return self._pack_text_resp(ctx, status.to_json(), "text/plain")

        async def _healthz(ctx: HttpRequestCtx) -> HttpResp:
            health = await self._metric_client.get_health_status()
            if health.status == health.status.Good:
                return self._pack_text_resp(ctx, "ok", "text/plain")

            return self._pack_error_resp(
                ctx,
                body=(
                    "<html><body>"
                    "<h2>Unhealthy</h2>"
                    f"<h1>{health.errorService}</h1>"
                    f"<h1>{health.errorMessage}</h1>"
                    "</body></html>"
                ),
                status_code=503,
                content_type="text/html",
            )

        self.add_get_route("/", _index)
        self.add_get_route("/robots.txt", _robot_txt)
        self.add_get_route(metric_url, _metric)
        self.add_get_route(status_url, _status)
        self.add_get_route(healthz_url, _healthz)

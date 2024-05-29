from __future__ import annotations

import asyncio

import aioprometheus.service as _srv

from .metric import StatRegistry
from ..config.config import Config


class PrometheusServer:
    def __init__(self, cfg: Config, registry: StatRegistry) -> None:
        self._cfg = cfg
        self._prometheus = _srv.Service(registry)
        self._start_task: asyncio.Task | None = None

    def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._start_task = loop.create_task(self._prometheus.start(addr="0.0.0.0", port=self._cfg.stat_public_port))

    def stop(self) -> None:
        self._start_task = None
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._prometheus.stop())

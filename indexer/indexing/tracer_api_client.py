from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import aiochclient as _ch
import aiohttp as _cl

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.utils.cached import cached_property

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ChConnection:
    ch_dsn: str
    _is_connected: bool = False

    async def close(self) -> None:
        if self._is_connected:
            await self.ch_client.close()

    @cached_property
    def ch_client(self) -> _ch.ChClient:
        object.__setattr__(self, "_is_connected", True)
        ch_session = _cl.ClientSession()
        return _ch.ChClient(ch_session, url=self.ch_dsn)


class TracerApiClient:
    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(cfg)
        self._ch_conn_list: list[_ChConnection] = list()

        for ch_dsn in cfg.ch_dsn_list:
            try:
                ch_conn = _ChConnection(ch_dsn=ch_dsn)
                self._ch_conn_list.append(ch_conn)
            except (BaseException,):
                _LOG.error("bad address in the clickhouse connection list")

        self._last_ch_conn_idx = 0

        request = f""";
            SELECT DISTINCT slot
              FROM events.update_account_distributed
             WHERE slot <= (
            SELECT max(slot) - {self._cfg.slot_processing_delay}
              FROM events.update_account_distributed
            )
             ORDER BY slot DESC
             LIMIT {max(self._cfg.slot_processing_delay, 1)}
        """
        self._request = " ".join(request.split()).strip("; ")

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        await asyncio.gather(*[ch_conn.close() for ch_conn in self._ch_conn_list])

    async def get_max_slot(self) -> int | None:
        if not self._ch_conn_list:
            return None

        while True:
            self._last_ch_conn_idx += 1
            if self._last_ch_conn_idx == len(self._ch_conn_list):
                self._last_ch_conn_idx = 0

            ch_conn = self._ch_conn_list[self._last_ch_conn_idx]
            try:
                row_list = await ch_conn.ch_client.fetch(self._request)
                if not row_list:
                    return None

                slot = row_list[-1][0]
                return slot

            except BaseException as exc:
                _LOG.error("unknown fail to fetch slot from ClickHouse", exc_info=exc, extra=self._msg_filter)
                await asyncio.sleep(0.5)

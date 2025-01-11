from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Final

from common.config.config import Config
from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.utils.json_logger import logging_context
from .sender_nonce import SenderNonce
from ..base.mp_api import MpTxModel, MpTxExecPctModel

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _LRUItem:
    start_time_sec: int
    tx: MpTxModel


@dataclass
class _TxItem:
    tx: MpTxModel
    exec_pct_list: list[MpTxExecPctModel]


class MpTxDict:
    def __init__(self, cfg: Config):
        self._tx_hash_dict: dict[EthTxHash, _TxItem] = dict()
        self._sender_nonce_dict: dict[SenderNonce, _TxItem] = dict()
        self._tx_queue: deque[_LRUItem] = deque()
        self._clear_time_sec: Final[int] = cfg.mp_cache_life_sec

        self._stop_event = asyncio.Event()
        self._clear_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._clear_task = asyncio.create_task(self._clear_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._clear_task:
            await self._clear_task

    def __contains__(self, neon_tx_hash: EthTxHash) -> bool:
        return neon_tx_hash in self._tx_hash_dict

    def add_tx(self, tx: MpTxModel) -> None:
        # _LOG.debug("add tx %s to tx-cache", tx)

        item = _TxItem(tx=tx, exec_pct_list=list())
        self._tx_hash_dict[tx.neon_tx_hash] = item
        self._sender_nonce_dict[SenderNonce.from_raw(tx)] = item

    def done_tx(self, neon_tx_hash: EthTxHash) -> None:
        if item := self._tx_hash_dict.get(neon_tx_hash):
            lru = _LRUItem(start_time_sec=int(time.monotonic()), tx=item.tx)
            self._tx_queue.append(lru)

    def pop_tx(self, neon_tx_hash: EthTxHash) -> None:
        if item := self._tx_hash_dict.pop(neon_tx_hash, None):
            self._sender_nonce_dict.pop(SenderNonce.from_raw(item.tx), None)

    def notify_exec_pct(self, base_tx_hash: EthTxHash, neon_tx_hash: EthTxHash, exec_pct: int) -> bool:
        if not (item := self._tx_hash_dict.get(base_tx_hash, None)):
            return False

        if (idx := next((idx for idx, v in enumerate(item.exec_pct_list) if v.neon_tx_hash == neon_tx_hash), -1)) != -1:
            item.exec_pct_list.pop(idx)
        item.exec_pct_list.append(MpTxExecPctModel(neon_tx_hash=neon_tx_hash, exec_pct=exec_pct))
        return True

    def get_tx_by_hash(self, neon_tx_hash: EthTxHash) -> MpTxModel | None:
        return item.tx if (item := self._tx_hash_dict.get(neon_tx_hash, None)) else None

    def get_tx_by_sender_nonce(self, neon_address: NeonAddress, tx_nonce: int) -> MpTxModel | None:
        key = SenderNonce.from_raw((neon_address.eth_address, neon_address.chain_id, tx_nonce))
        return item.tx if (item := self._sender_nonce_dict.get(key, None)) else None

    def get_exec_pct_list(self, neon_tx_hash: EthTxHash) -> list[MpTxExecPctModel]:
        return list() if not (item := self._tx_hash_dict.get(EthTxHash.from_raw(neon_tx_hash))) else item.exec_pct_list

    async def _clear_loop(self) -> None:
        next_item_sec = 0
        base_sleep_sec: Final[int] = self._clear_time_sec // 10
        stop_task = asyncio.create_task(self._stop_event.wait())
        with logging_context(ctx="mp-clear-tx-cache"):
            while not self._stop_event.is_set():
                try:
                    next_item_sec = await self._clear()
                except BaseException as exc:
                    _LOG.error("error on clearing tx-cache", exc_info=exc)

                sleep_sec = (next_item_sec - int(time.monotonic())) if next_item_sec else base_sleep_sec
                await asyncio.wait({stop_task}, timeout=sleep_sec)

    async def _clear(self) -> int:
        if not self._tx_queue:
            return 0

        clear_time_sec = int(time.monotonic()) - self._clear_time_sec
        while self._tx_queue and (self._tx_queue[0].start_time_sec < clear_time_sec):
            item = self._tx_queue.popleft()
            self._tx_hash_dict.pop(item.tx.neon_tx_hash, None)
            self._sender_nonce_dict.pop(SenderNonce.from_raw(item.tx), None)
            # _LOG.debug("remove %s from tx-cache", item.tx)

        return self._tx_queue[0].start_time_sec + self._clear_time_sec + 1 if self._tx_queue else 0

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Final

from common.config.config import Config
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.utils.json_logger import logging_context
from .sender_nonce import SenderNonce
from ..base.mp_api import MpTxModel

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Item:
    start_time_sec: int
    tx: MpTxModel


class MpTxDict:
    def __init__(self, cfg: Config):
        self._tx_hash_dict: dict[EthTxHash, MpTxModel] = dict()
        self._sender_nonce_dict: dict[SenderNonce, MpTxModel] = dict()
        self._tx_queue: deque[_Item] = deque()
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
        _LOG.debug("add tx %s to tx-cache", tx)
        self._tx_hash_dict[tx.neon_tx_hash] = tx
        self._sender_nonce_dict[SenderNonce.from_raw(tx)] = tx

    def done_tx(self, neon_tx_hash: EthTxHash) -> None:
        if tx := self._tx_hash_dict.get(neon_tx_hash):
            item = _Item(start_time_sec=int(time.monotonic()), tx=tx)
            self._tx_queue.append(item)

    def pop_tx(self, neon_tx_hash: EthTxHash) -> None:
        self._tx_hash_dict.pop(neon_tx_hash, None)

    def get_tx_by_hash(self, neon_tx_hash: EthTxHash) -> NeonTxModel | None:
        if tx := self._tx_hash_dict.get(neon_tx_hash, None):
            return tx.neon_tx
        return None

    def get_tx_by_sender_nonce(self, neon_account: NeonAccount, tx_nonce: int) -> NeonTxModel | None:
        key = SenderNonce.from_raw((neon_account.eth_address, neon_account.chain_id, tx_nonce))
        if tx := self._sender_nonce_dict.get(key, None):
            return tx.neon_tx
        return None

    async def _clear_loop(self) -> None:
        next_item_sec = 0
        base_sleep_sec: Final[int] = self._clear_time_sec // 10
        with logging_context(ctx="mp-clear-tx-cache"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    sleep_sec = (next_item_sec - int(time.monotonic())) if next_item_sec else base_sleep_sec
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    next_item_sec = await self._clear()
                except BaseException as exc:
                    _LOG.error("error on clearing tx-cache", exc_info=exc)

    async def _clear(self) -> int:
        if not self._tx_queue:
            return 0

        clear_time_sec = int(time.monotonic()) - self._clear_time_sec
        while self._tx_queue and (self._tx_queue[0].start_time_sec < clear_time_sec):
            item = self._tx_queue.popleft()
            self._tx_hash_dict.pop(item.tx.neon_tx_hash, None)
            self._sender_nonce_dict.pop(SenderNonce.from_raw(item.tx), None)
            _LOG.debug("remove %s from tx-cache", item.tx)

        return self._tx_queue[0].start_time_sec + self._clear_time_sec + 1 if self._tx_queue else 0

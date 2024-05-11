from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.hash import EthTxHash
from common.utils.json_logger import log_msg, logging_context
from indexer.db.indexer_db_client import IndexerDbClient
from ..base.mp_api import MpStuckTxModel

_LOG = logging.getLogger(__name__)


class MpStuckTxDict:
    def __init__(self) -> None:
        self._tx_dict: dict[EthTxHash, MpStuckTxModel] = dict()
        self._processing_tx_dict: dict[EthTxHash, MpStuckTxModel] = dict()

        self._db: IndexerDbClient | None = None
        self._stop_event = asyncio.Event()
        self._scan_stuck_tx_task: asyncio.Task | None = None

    async def start(self, db: IndexerDbClient) -> None:
        self._db = db
        self._scan_stuck_tx_task = asyncio.create_task(self._scan_stuck_tx_loop())

    async def stop(self) -> None:
        if self._scan_stuck_tx_task:
            self._stop_event.set()
            await self._scan_stuck_tx_task

    @property
    def tx_cnt(self) -> int:
        return len(self._tx_dict)

    @property
    def processing_tx_cnt(self) -> int:
        return len(self._processing_tx_dict)

    def peek_tx(self) -> MpStuckTxModel | None:
        return next(iter(self._tx_dict.values()), None)

    def acquire_tx(self, stuck_tx: MpStuckTxModel) -> None:
        self._pop_tx(stuck_tx)
        self._processing_tx_dict[stuck_tx.neon_tx_hash] = stuck_tx
        _LOG.debug(log_msg("start processing of stuck tx {StuckTx}", StuckTx=stuck_tx))

    def skip_tx(self, stuck_tx: MpStuckTxModel) -> None:
        self._pop_tx(stuck_tx)
        _LOG.debug(log_msg("skip stuck tx {StuckTx}", StuckTx=stuck_tx))

    def done_tx(self, stuck_tx: MpStuckTxModel) -> None:
        self._done_tx(stuck_tx)
        _LOG.debug(log_msg("done stuck tx {StuckTx}", StuckTx=stuck_tx))

    def fail_tx(self, stuck_tx: MpStuckTxModel) -> None:
        self._done_tx(stuck_tx)
        _LOG.debug(log_msg("fail stuck tx {StuckTx}", StuckTx=stuck_tx))

    def cancel_tx(self, stuck_tx: MpStuckTxModel) -> None:
        self._done_tx(stuck_tx)
        self._tx_dict[stuck_tx.neon_tx_hash] = stuck_tx
        _LOG.debug(log_msg("cancel stuck tx {StuckTx}", StuckTx=stuck_tx))

    def _pop_tx(self, stuck_tx: MpStuckTxModel) -> MpStuckTxModel:
        popped_tx = self._tx_dict.pop(stuck_tx.neon_tx_hash, None)
        assert popped_tx, f"{stuck_tx.neon_tx_hash} not found in the list of stuck txs"
        return popped_tx

    def _done_tx(self, stuck_tx: MpStuckTxModel) -> MpStuckTxModel:
        popped_tx = self._processing_tx_dict.pop(stuck_tx.neon_tx_hash, None)
        assert popped_tx, f"{stuck_tx.neon_tx_hash} not found in the list of stuck txs"
        return popped_tx

    async def _scan_stuck_tx_loop(self) -> None:
        sleep_sec: Final[float] = ONE_BLOCK_SEC * 3
        with logging_context(ctx="mp-scan-stuck-txs"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    await self._scan_stuck_tx()
                except BaseException as exc:
                    _LOG.error("error on scan", exc_info=exc)

    async def _scan_stuck_tx(self) -> None:
        _, src_tx_list = await self._db.get_stuck_neon_tx_list()
        if not src_tx_list:
            return

        tx_dict: dict[EthTxHash, MpStuckTxModel] = dict()
        for data in src_tx_list:
            stuck_tx = MpStuckTxModel.from_db(data)
            if stuck_tx.neon_tx_hash in self._processing_tx_dict:
                continue
            elif stuck_tx.neon_tx_hash not in self._tx_dict:
                _LOG.debug(log_msg("found external stuck tx {StuckTx}", StuckTx=stuck_tx))

            tx_dict[stuck_tx.neon_tx_hash] = stuck_tx
        self._tx_dict = tx_dict

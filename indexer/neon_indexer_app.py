from __future__ import annotations

import asyncio
import logging
import multiprocessing as mp
from typing import Sequence

import uvloop

from common.config.config import Config, StartSlot
from common.config.constants import NEON_PROXY_VER
from common.config.utils import LogMsgFilter
from common.db.db_connect import DbConnection
from common.neon_rpc.client import CoreApiClient
from common.neon_rpc.server import CoreApiServer
from common.solana_rpc.client import SolClient
from common.solana_rpc.not_empty_block import SolFirstBlockFinder, SolNotEmptyBlockFinder
from common.utils.json_logger import Logger, logging_context
from .db.indexer_db import IndexerDb, IndexerDbSlotRange
from .indexing.indexer import Indexer
from .indexing.tracer_api_client import TracerApiClient
from .stat.client import StatClient
from .stat.server import StatServer

_LOG = logging.getLogger(__name__)


class NeonIndexerApp:
    def __init__(self):
        Logger.setup()
        cfg = Config()
        _LOG.info("running NeonIndexer %s with the config: %s", NEON_PROXY_VER, cfg.to_string())

        self._cfg = cfg
        self._msg_filter = LogMsgFilter(cfg)
        self._sol_client = SolClient(cfg)
        self._core_api_server = CoreApiServer(cfg)
        self._stat_server = StatServer(cfg)

        db_conn = DbConnection(self._cfg)
        db_conn.enable_debug_query()
        self._db = IndexerDb(self._cfg, db_conn)

        self._first_slot = 0
        self._start_slot = 0
        self._last_known_slot = 0
        self._finalized_slot = 0

        self._reindex_ident = ""
        self._reindex_start_slot: int | None = None
        self._reindex_stop_slot = 0
        self._reindex_process_list: list[_ReIndexer] = list()

    def start(self) -> int:
        exit_code = uvloop.run(self._run())
        return exit_code

    async def _run(self) -> int:
        try:
            self._core_api_server.start()
            self._stat_server.start()

            await self._db.start()
            await self._db.init_slot_range()
            await self._init_slot_range()

            if reindex_slot_range_list := await self._get_reindex_slot_range_list():
                self._run_reindexing(reindex_slot_range_list)

            if self._cfg.start_slot == StartSlot.Disable:
                # if indexing is disabled just wait for finishing the reindexing processes
                for reindexer in self._reindex_process_list:
                    reindexer.join()
            else:
                await self._run_indexing()

            await self._db.stop()
            self._stat_server.stop()
            self._core_api_server.stop()
            return 0

        except BaseException as exc:
            _LOG.error("error on Indexer run", exc_info=exc, extra=self._msg_filter)
            return 1

    async def _run_indexing(self) -> None:
        core_api_client = CoreApiClient(cfg=self._cfg, sol_client=self._sol_client)
        tracer_api_client = TracerApiClient(cfg=self._cfg)
        stat_client = StatClient(self._cfg)

        indexer = Indexer(
            self._cfg,
            self._sol_client,
            core_api_client,
            tracer_api_client,
            stat_client,
            self._db,
        )

        await self._sol_client.start()
        await core_api_client.start()
        await stat_client.start()
        await tracer_api_client.start()

        await indexer.run()

        await core_api_client.stop()
        await tracer_api_client.stop()
        await stat_client.stop()
        await self._sol_client.stop()

    async def _init_slot_range(self) -> None:
        block_finder = SolFirstBlockFinder(self._sol_client)

        self._first_slot = await block_finder.find_slot()
        self._finalized_slot = await block_finder.get_stop_slot()
        self._last_known_slot = self._db.get_min_used_slot()

        if self._cfg.start_slot == StartSlot.Disable:
            self._reindex_stop_slot = self._get_reindex_stop_or_finalized_slot()
            _LOG.debug("%s=%s, skip indexing...", self._cfg.start_slot_name, self._cfg.start_slot)
            return

        self._start_slot = self._get_cfg_start_slot()
        # reindexing should stop on the start slot of indexing
        self._reindex_stop_slot = self._start_slot

    async def _get_reindex_stop_or_finalized_slot(self) -> int:
        """
        If it is the first start with disabling indexing,
        then collect information about blocks in the Solana
        """
        finalized_slot = await self._db.get_finalized_slot()
        if finalized_slot != 0:
            return finalized_slot

        return self._finalized_slot

    async def _get_reindex_slot_range_list(
        self,
    ) -> tuple[IndexerDbSlotRange, ...]:
        self._reindex_start_slot, self._reindex_ident = self._get_cfg_reindex_start_slot()

        if (self._reindex_start_slot is None) or (not self._cfg.reindex_thread_cnt):
            _LOG.info(
                "skip reindexing: %s=%s, %s=%s",
                self._cfg.reindex_start_slot_name,
                self._reindex_ident,
                self._cfg.reindex_thread_cnt_name,
                self._cfg.reindex_thread_cnt,
            )
            return tuple()

        slot_range_list = await self._load_exist_reindex_range_list()
        if await self._is_reindex_completed(slot_range_list):
            return tuple()

        slot_range_list = await self._add_new_reindex_range_list(slot_range_list)
        for slot_range in slot_range_list:
            await self._db.constant_db.set(None, slot_range.start_slot_name, slot_range.start_slot)
            await self._db.constant_db.set(None, slot_range.min_used_slot_name, slot_range.min_used_slot)
            await self._db.constant_db.set(None, slot_range.stop_slot_name, slot_range.stop_slot)
        return slot_range_list

    async def _is_reindex_completed(self, slot_range_list: Sequence[IndexerDbSlotRange]) -> bool:
        reindex_ident_name = "reindex_ident"

        if self._reindex_ident == StartSlot.Continue:
            # each restart adds the range from the last parsed slot to the current finalized slot to reindexing ranges
            await self._db.constant_db.set(None, reindex_ident_name, self._reindex_ident)
            return False

        last_reindex_ident = await self._db.constant_db.get_str(None, reindex_ident_name, "<NULL>")
        if (last_reindex_ident == self._reindex_ident) and (not len(slot_range_list)):
            _LOG.info("reindexing %s=%s was completed...", self._cfg.reindex_start_slot_name, self._reindex_ident)
            return True

        await self._db.constant_db.set(None, reindex_ident_name, self._reindex_ident)
        return False

    async def _load_exist_reindex_range_list(self) -> tuple[IndexerDbSlotRange, ...]:
        slot_range_list: list[IndexerDbSlotRange] = list()

        key_list = await self._db.constant_db.get_key_list(None)
        for key in key_list:
            # For example: CONTINUE:213456789:starting_slot
            key_part_list = key.split(":")
            if len(key_part_list) != 3:
                continue

            reindex_ident, start_slot, _ = key_part_list
            slot_range = IndexerDbSlotRange(reindex_ident, int(start_slot))
            if slot_range.stop_slot_name != key:
                continue

            if self._reindex_ident != slot_range.reindex_ident:
                _LOG.info("skip the old REINDEX range %s", slot_range)
                await _done_slot_range(self._db, slot_range)
                continue

            slot_range = await self._load_slot_range(slot_range)
            if self._first_slot > slot_range.stop_slot:
                _LOG.info(
                    "skip the lost REINDEX range %s: first slot (%s) > db.stop_slot (%s)",
                    slot_range,
                    self._first_slot,
                    slot_range.stop_slot,
                )
                await _done_slot_range(self._db, slot_range)
            else:
                _LOG.info("load the REINDEX range %s", slot_range)
                slot_range_list.append(slot_range)

        slot_range_list = sorted(slot_range_list, key=lambda x: x.start_slot)
        return tuple(slot_range_list)

    async def _load_slot_range(self, slot_range: IndexerDbSlotRange) -> IndexerDbSlotRange:
        start_slot = await self._db.constant_db.get_int(None, slot_range.start_slot_name, self._last_known_slot)
        min_used_slot = await self._db.constant_db.get_int(None, slot_range.min_used_slot_name, start_slot)
        stop_slot = await self._db.constant_db.get_int(None, slot_range.stop_slot_name, slot_range.max_slot)
        return IndexerDbSlotRange(slot_range.reindex_ident, start_slot, min_used_slot, stop_slot)

    async def _add_new_reindex_range_list(
        self, slot_range_list: Sequence[IndexerDbSlotRange]
    ) -> tuple[IndexerDbSlotRange, ...]:
        start_slot = max(self._reindex_start_slot, self._first_slot)
        if len(slot_range_list):
            start_slot = max(slot_range_list[-1].stop_slot, start_slot)
        avail_cnt = max(1, self._cfg.reindex_max_range_cnt - len(slot_range_list))
        new_slot_range_list = await self._build_new_reindex_range_list(start_slot, avail_cnt)

        return await self._merge_slot_range_list(slot_range_list, new_slot_range_list)

    async def _build_new_reindex_range_list(self, start_slot: int, avail_cnt: int) -> tuple[IndexerDbSlotRange, ...]:
        """
        Reindex slots between the reindexing start slot and indexing start slot.
        Check that the number of ranges is not exceeded.
        """
        total_len = self._reindex_stop_slot - start_slot + 1
        if total_len <= 0:
            return tuple()

        need_cnt = int(total_len / self._cfg.reindex_range_len) + 1
        avail_cnt = max(1, min(avail_cnt, need_cnt))
        range_len = int(total_len / avail_cnt) + 1

        finalized_slot = self._finalized_slot

        slot_range_list: list[IndexerDbSlotRange] = list()
        while start_slot < self._reindex_stop_slot:
            block_finder = SolNotEmptyBlockFinder(self._sol_client, start_slot=start_slot, stop_slot=finalized_slot)
            start_slot = await block_finder.find_slot()

            stop_slot = min(start_slot + range_len, self._reindex_stop_slot)

            slot_range = IndexerDbSlotRange(self._reindex_ident, start_slot, start_slot, stop_slot)
            slot_range_list.append(slot_range)

            start_slot = stop_slot

        return tuple(slot_range_list)

    async def _merge_slot_range_list(
        self,
        slot_range_list: Sequence[IndexerDbSlotRange],
        new_slot_range_list: Sequence[IndexerDbSlotRange],
    ) -> tuple[IndexerDbSlotRange, ...]:
        """
        If it is the fast restart, the number of slots between restarts is small.
        So here we are trying to squash the last range from the last restart with the new first range.
        """
        merged_slot_range: IndexerDbSlotRange | None = None

        def _merge() -> tuple[IndexerDbSlotRange, ...]:
            _slot_range_list = list(slot_range_list)
            if merged_slot_range is not None:
                _slot_range_list.append(merged_slot_range)
            _slot_range_list.extend(new_slot_range_list)
            return tuple(_slot_range_list)

        if (not slot_range_list) or (not new_slot_range_list):
            return _merge()

        new = new_slot_range_list[0]
        old = slot_range_list[-1]
        if new.start_slot - old.stop_slot > self._cfg.reindex_range_len:
            return _merge()

        merged_slot_range = IndexerDbSlotRange(self._reindex_ident, old.start_slot, old.min_used_slot, new.stop_slot)
        await self._db.constant_db.set(None, merged_slot_range.stop_slot_name, merged_slot_range.stop_slot)

        slot_range_list = slot_range_list[:-1]
        new_slot_range_list = new_slot_range_list[1:]
        return _merge()

    def _get_cfg_start_slot(self) -> int:
        cfg_start_slot = self._get_cfg_start_slot_impl()

        start_slot = max(cfg_start_slot, self._first_slot)
        _LOG.info(
            "FIRST_AVAILABLE_SLOT=%s, FINALIZED_SLOT=%s, %s=%s, started from the slot %s",
            self._first_slot,
            self._finalized_slot,
            self._cfg.start_slot_name,
            cfg_start_slot,
            start_slot,
        )
        return start_slot

    def _get_cfg_start_slot_impl(self) -> int:
        """
        This function allow to skip a part of history.
        - LATEST - start from the last block slot from Solana
        - CONTINUE - the first start from the LATEST, on next starts from the last parsed slot
        - INTEGER - the first start from the INTEGER, on next starts CONTINUE
        """
        last_known_slot = 0 if not isinstance(self._last_known_slot, int) else self._last_known_slot

        start_slot_name = self._cfg.start_slot_name
        start_slot = self._cfg.start_slot
        _LOG.info("starting with LAST_KNOWN_SLOT=%s and %s=%s", last_known_slot, start_slot_name, start_slot)

        def _finalized_slot(reason: str) -> int:
            _LOG.info(
                "%s=%s%s, forced to use the FINALIZED_SLOT %s",
                start_slot_name,
                start_slot,
                reason,
                self._finalized_slot,
            )
            return self._finalized_slot

        if isinstance(start_slot, int):
            if start_slot > self._finalized_slot:
                return _finalized_slot(f", the {start_slot_name} is bigger than the FINALIZED_SLOT")

        elif start_slot not in (StartSlot.Continue, StartSlot.Latest):
            _LOG.error("wrong value %s=%s, forced to use 0", start_slot_name, start_slot)
            start_slot = 0

        if start_slot == StartSlot.Continue:
            if last_known_slot > 0:
                _LOG.info("%s=%s, use the LAST_KNOWN_SLOT %s", start_slot_name, start_slot, last_known_slot)
                return last_known_slot
            else:
                return _finalized_slot(", the LAST_KNOWN_SLOT doesn't exist")

        elif start_slot == StartSlot.Latest:
            return _finalized_slot("")

        assert isinstance(start_slot, int)
        if start_slot < last_known_slot:
            _LOG.info(
                "%s=%s, force to use the LAST_KNOWN_SLOT %s",
                self._cfg.start_slot_name,
                start_slot,
                last_known_slot,
            )
            return last_known_slot

        _LOG.info("%s=%s, start from %s", self._cfg.start_slot_name, start_slot, start_slot)
        return start_slot

    def _get_cfg_reindex_start_slot(self) -> tuple[int | None, str]:
        """
        Valid variants:
        REINDEXER_START_SLOT=CONTINUE, START_SLOT=LATEST
        REINDEXER_START_SLOT=10123456, START_SLOT=CONTINUE
        REINDEXER_START_SLOT=10123456, START_SLOT=LATEST
        REINDEXER_START_SLOT=10123456, START_SLOT=100
        """
        reindex_ident = self._cfg.reindex_start_slot

        if isinstance(reindex_ident, int):
            if reindex_ident >= self._finalized_slot:
                _LOG.error("%s=%s is too big, skip reindexing...", self._cfg.reindex_start_slot_name, reindex_ident)
                return None, ""

            # start from the slot which Solana knows
            start_slot = reindex_ident
            reindex_ident = str(start_slot)

            _LOG.info(
                "%s=%s, start reindexing from the slot %s",
                self._cfg.reindex_start_slot_name,
                reindex_ident,
                start_slot,
            )
            return start_slot, reindex_ident

        elif reindex_ident == StartSlot.Disable:
            return None, ""

        elif reindex_ident == StartSlot.Continue:
            if self._cfg.start_slot not in (StartSlot.Latest, StartSlot.Disable):
                _LOG.error(
                    "wrong value %s=%s, it is valid only for %s=(%s), skip reindexing...",
                    self._cfg.reindex_start_slot_name,
                    StartSlot.Continue,
                    self._cfg.start_slot_name,
                    (StartSlot.Latest, StartSlot.Disable),
                    self._cfg.reindex_start_slot_name,
                )
                return None, ""

            # self._last_known_slot = 0 - it happens if it is the first start
            # and the ReIndexer cannot start from the slot which Solana doesn't know
            start_slot = max(self._first_slot, (self._last_known_slot or self._finalized_slot))

            _LOG.info(
                "%s=%s, started reindexing from the slot %s",
                self._cfg.reindex_start_slot_name,
                StartSlot.Continue,
                start_slot,
            )
            return start_slot, reindex_ident

        _LOG.error("wrong value %s=%s, skip reindexing...", self._cfg.reindex_start_slot_name, reindex_ident)
        return None, ""

    def _run_reindexing(self, slot_range_list: Sequence[IndexerDbSlotRange]) -> None:
        """
        Split the DB list so that the last start slots are indexed by the first

        For example:

        self._cfg.reindex_thread_cnt = 2
        I -> IndexerDb
        S -> start_slot
        I(S=1) -> IndexerDB(start_slot=1)

        [I(S=1000), I(S=10), I(S=11), I(S=12), I(S=102)]

        ReIndexer(0): [I(S=10), I(S=12),  I(S=1000)]
        ReIndexer(1): [I(S=11), I(S=102)]
        """
        slot_range_list = sorted(slot_range_list, key=lambda x: x.start_slot, reverse=True)
        slot_range_list_list: list[list[IndexerDbSlotRange]] = [list() for _ in range(self._cfg.reindex_thread_cnt)]

        idx = 0
        while len(slot_range_list) > 0:
            db = slot_range_list.pop()
            slot_range_list_list[idx].append(db)
            idx += 1
            if idx >= self._cfg.reindex_thread_cnt:
                idx = 0

        for idx in range(self._cfg.reindex_thread_cnt):
            slot_range_list = slot_range_list_list[idx]
            if not slot_range_list:
                break

            reindexer = _ReIndexer(idx, self._cfg, slot_range_list)
            self._reindex_process_list.append(reindexer)
            reindexer.start()


class _ReIndexer:
    def __init__(
        self,
        idx: int,
        cfg: Config,
        slot_range_list: Sequence[IndexerDbSlotRange],
    ):
        self._idx = idx
        self._cfg = cfg
        self._slot_range_list = slot_range_list
        self._process: mp.Process | None = None

    def start(self) -> None:
        """Python has GIL... It can be resolved with separate processes"""
        self._process = mp.Process(target=self._start)
        self._process.start()

    def join(self) -> None:
        if self._process:
            self._process.join()

    def _start(self) -> None:
        _LOG.info(f"start ReIndexer(%s)", self._idx)
        uvloop.run(self._run())

    async def _run(self) -> None:
        """Under the hood it runs the Indexer but in a limited range of slots."""

        msg_filter = LogMsgFilter(self._cfg)

        try:
            sol_client = SolClient(self._cfg)
            core_api_client = CoreApiClient(cfg=self._cfg, sol_client=sol_client)
            stat_client = StatClient(self._cfg)

            db_conn = DbConnection(self._cfg)
            db = IndexerDb(self._cfg, db_conn)

            await sol_client.start()
            await core_api_client.start()
            await stat_client.start()
            await db.start()
        except BaseException as exc:
            _LOG.error("error on ReIndexer initialization", exc_info=exc, extra=msg_filter)
            return

        for slot_range in self._slot_range_list:
            with logging_context(reindex=slot_range.reindex_ident):
                try:
                    _LOG.info(
                        "start the reindexing of the range %s(->%s):%s on the ReIndexer(%s)",
                        slot_range.start_slot,
                        slot_range.min_used_slot,
                        slot_range.stop_slot,
                        self._idx,
                    )

                    db.set_slot_range(slot_range)
                    indexer = Indexer(self._cfg, sol_client, core_api_client, None, stat_client, db)
                    await indexer.run()
                    await _done_slot_range(db, slot_range)

                    _LOG.info(
                        "done the reindexing of the range %s:%s on the ReIndexer(%s)",
                        slot_range.start_slot,
                        slot_range.stop_slot,
                        self._idx,
                    )
                except BaseException as exc:
                    _LOG.error("error on ReIndexer run", exc_info=exc, extra=msg_filter)

        await asyncio.sleep(3)
        await db.stop()
        await sol_client.stop()
        await core_api_client.stop()
        await stat_client.stop()


async def _done_slot_range(db: IndexerDb, slot_range: IndexerDbSlotRange) -> None:
    slot_name_list = [slot_range.start_slot_name, slot_range.stop_slot_name, slot_range.min_used_slot_name]
    await db.constant_db.delete_list(None, slot_name_list)

from __future__ import annotations

import asyncio
import logging

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.neon_rpc.client import CoreApiClient
from common.solana.block import SolRpcBlockInfo
from common.solana.commit_level import SolCommit
from common.solana_rpc.client import SolClient
from common.solana_rpc.not_empty_block import SolFirstBlockFinder, SolNotEmptyBlockFinder
from common.utils.json_logger import logging_context, log_msg
from common.utils.metrics_logger import MetricsLogger
from .alt_ix_collector import SolAltTxIxCollector
from .stuck_obj_validator import StuckObjectValidator
from .tracer_api_client import TracerApiClient
from ..base.errors import SolHistoryError, SolFailedHistoryError
from ..base.neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from ..base.neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonDecoderCtx, SolNeonDecoderStat
from ..base.solana_block_net_cache import SolBlockNetCache
from ..db.indexer_db import IndexerDb
from ..stat.client import StatClient
from ..stat.api import NeonBlockStat, NeonReindexBlockStat, NeonDoneReindexStat

_LOG = logging.getLogger(__name__)


class Indexer:
    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        core_api_client: CoreApiClient,
        tracer_api_client: TracerApiClient | None,
        stat_client: StatClient,
        db: IndexerDb,
    ) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._db = db

        self._tracer_api_client = tracer_api_client

        self._msg_filter = LogMsgFilter(cfg)
        self._counted_logger = MetricsLogger(cfg.metrics_log_skip_cnt)
        self._stat_client = stat_client

        self._last_processed_slot = 0
        self._last_confirmed_slot = 0
        self._last_finalized_slot = 0
        self._last_tracer_slot: int | None = None
        self._neon_block_dict = NeonIndexedBlockDict()

        self._stuck_obj_validator = StuckObjectValidator(cfg, sol_client, core_api_client)
        self._alt_ix_collector = SolAltTxIxCollector(cfg, sol_client)
        self._sol_block_net_cache = SolBlockNetCache(cfg, sol_client)

        self._term_slot = min(db.stop_slot + self._alt_ix_collector.check_depth, db.term_slot)

        self._decoder_stat = SolNeonDecoderStat()

        sol_neon_ix_decoder_list: list[type[DummyIxDecoder]] = list()
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_list())
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_deprecated_list())

        self._sol_neon_ix_decoder_dict: dict[int, type[DummyIxDecoder]] = dict()
        for _SolNeonIxDecoder in sol_neon_ix_decoder_list:
            ix_code = _SolNeonIxDecoder.ix_code
            _LOG.debug("register decoder: 0x%02x:%s", ix_code.value, ix_code.name)
            assert ix_code not in self._sol_neon_ix_decoder_dict
            self._sol_neon_ix_decoder_dict[ix_code] = _SolNeonIxDecoder

    async def _save_checkpoint(self, dctx: SolNeonDecoderCtx) -> None:
        if dctx.is_neon_block_queue_empty:
            return

        neon_block_queue = dctx.neon_block_queue
        neon_block = neon_block_queue[-1]
        await self._alt_ix_collector.collect_in_block(neon_block)

        # validate stuck objects only on the last not-finalized block
        if not neon_block.is_finalized:
            await self._stuck_obj_validator.validate_block(neon_block)
        else:
            self._neon_block_dict.finalize_neon_block(neon_block)
            self._sol_block_net_cache.finalize_block(neon_block.slot)

        if (not self._db.is_reindexing_mode) and (not neon_block.is_done):
            neon_block.check_stuck_objs(self._cfg)
        await self._db.submit_block_list(self._neon_block_dict.min_slot, neon_block_queue)
        dctx.clear_neon_block_queue()

    def _complete_neon_block(self, dctx: SolNeonDecoderCtx) -> None:
        neon_block = dctx.neon_block
        neon_block.complete_block()
        self._neon_block_dict.add_neon_block(neon_block)
        self._last_processed_slot = neon_block.slot
        self._commit_progress_stat()
        self._print_progress_stat()

    async def _add_neon_block_to_queue(self, dctx: SolNeonDecoderCtx) -> None:
        is_finalized = dctx.is_finalized
        neon_block = dctx.neon_block
        if is_finalized and (not neon_block.is_finalized):
            neon_block.mark_finalized()

        # in not-finalize mode: collect all blocks
        # in finalized mode: collect blocks by batches
        dctx.add_neon_block_to_queue()
        if is_finalized and dctx.is_neon_block_queue_full:
            await self._save_checkpoint(dctx)

    def _commit_progress_stat(self) -> None:
        """Send statistics for the current block's range"""
        if not self._cfg.gather_stat:
            return

        if self._db.reindex_ident:
            block_stat = NeonReindexBlockStat(
                reindex_ident=self._db.reindex_ident,
                start_block=self._db.start_slot,
                parsed_block=self._last_processed_slot,
                stop_block=self._db.stop_slot,
                term_block=self._term_slot,
                corrupted_block_cnt=self._decoder_stat.neon_corrupted_block_cnt_diff,
            )
            self._stat_client.commit_reindex_block_stat(block_stat)
        else:
            block_stat = NeonBlockStat(
                start_block=self._db.start_slot,
                parsed_block=self._last_processed_slot,
                finalized_block=self._last_finalized_slot,
                confirmed_block=self._last_confirmed_slot,
                tracer_block=self._last_tracer_slot,
                corrupted_block_cnt=self._decoder_stat.neon_corrupted_block_cnt_diff,
            )
            self._stat_client.commit_block_stat(block_stat)

    def _print_progress_stat(self) -> None:
        if not self._counted_logger.is_print_time:
            return

        value_dict = {
            "start block slot": self._db.start_slot,
            "current block slot": self._last_processed_slot,
            "min used block slot": self._neon_block_dict.min_slot,
            "processing ms": self._decoder_stat.processing_time_msec,
            "processed solana blocks": self._decoder_stat.sol_block_cnt,
            "corrupted neon blocks": self._decoder_stat.neon_corrupted_block_cnt,
            "processed solana transactions": self._decoder_stat.sol_tx_meta_cnt,
            "processed neon instructions": self._decoder_stat.sol_neon_ix_cnt,
        }
        self._decoder_stat.reset()

        if not self._db.is_reindexing_mode:
            value_dict["confirmed block slot"] = self._last_confirmed_slot
            value_dict["finalized block slot"] = self._last_finalized_slot
            if self._last_tracer_slot is not None:
                value_dict["tracer block slot"] = self._last_tracer_slot
        else:
            value_dict["stop block slot"] = self._db.stop_slot
            value_dict["terminate block slot"] = self._term_slot

        with logging_context(ctx="stat"):
            self._counted_logger.print(value_dict)

    async def _new_neon_block(self, dctx: SolNeonDecoderCtx, sol_block: SolRpcBlockInfo) -> NeonIndexedBlockInfo:
        if not dctx.is_finalized:
            return NeonIndexedBlockInfo(sol_block)

        stuck_slot = sol_block.slot
        holder_slot, neon_holder_list = await self._db.get_stuck_neon_holder_list()
        tx_slot, neon_tx_list = await self._db.get_stuck_neon_tx_list()
        _, neon_alt_list = await self._db.get_stuck_neon_alt_list()

        if (holder_slot is not None) and (tx_slot is not None) and (holder_slot != tx_slot):
            _LOG.warning("holder stuck block %s != tx stuck block %s", holder_slot, tx_slot)
            stuck_slot = min(holder_slot, tx_slot)

        elif tx_slot is not None:
            stuck_slot = tx_slot

        elif holder_slot is not None:
            stuck_slot = holder_slot

        return NeonIndexedBlockInfo.from_stuck_data(
            sol_block, stuck_slot + 1, neon_holder_list, neon_tx_list, neon_alt_list
        )

    async def _locate_neon_block(self, dctx: SolNeonDecoderCtx, sol_block: SolRpcBlockInfo) -> NeonIndexedBlockInfo:
        # The same block
        if dctx.has_neon_block and (dctx.neon_block.slot == sol_block.slot):
            return dctx.neon_block

        if neon_block := self._neon_block_dict.find_neon_block(sol_block.slot):
            pass
        elif dctx.has_neon_block:
            if dctx.neon_block.slot != sol_block.parent_slot:
                raise SolHistoryError(f"Wrong root block {dctx.neon_block.slot} for the slot {sol_block.slot}")
            # _LOG.debug("Clone slot %s from %s", sol_block.slot, dctx.neon_block.slot)
            neon_block = NeonIndexedBlockInfo.from_block(dctx.neon_block, sol_block)
        else:
            # _LOG.debug("Create new block for slot %s", sol_block.slot)
            neon_block = await self._new_neon_block(dctx, sol_block)

        # The next step, the indexer chooses the next block and saves of the current block in DB, cache ...
        dctx.set_neon_block(neon_block)
        return neon_block

    async def _collect_neon_txs(self, dctx: SolNeonDecoderCtx, stop_slot: int, sol_commit: SolCommit) -> None:
        start_slot = self._db.get_min_used_slot()
        if root_neon_block := self._neon_block_dict.finalized_neon_block:
            start_slot = root_neon_block.slot

        if self._last_tracer_slot is not None:
            stop_slot = min(stop_slot, self._last_tracer_slot)
        if stop_slot <= start_slot:
            return
        dctx.set_slot_range(start_slot, stop_slot, sol_commit)

        async for sol_block in self._sol_block_net_cache.iter_block(dctx):
            neon_block = await self._locate_neon_block(dctx, sol_block)
            if neon_block.is_completed:
                await self._add_neon_block_to_queue(dctx)
                continue
            is_pre_stuck_block = neon_block.stuck_slot > neon_block.slot

            for sol_tx_meta in dctx.iter_sol_neon_tx_meta(sol_block):
                sol_tx_cost = sol_tx_meta.sol_tx_cost
                neon_block.add_sol_tx_cost(sol_tx_cost)

                for sol_neon_ix in dctx.iter_sol_neon_ix():
                    with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                        _SolNeonIxDecoder = self._sol_neon_ix_decoder_dict.get(sol_neon_ix.neon_ix_code, DummyIxDecoder)
                        sol_neon_ix_decoder = _SolNeonIxDecoder(dctx)
                        if is_pre_stuck_block and sol_neon_ix_decoder.is_stuck:
                            continue

                        neon_block.add_sol_neon_ix(sol_neon_ix)
                        if not sol_neon_ix.is_success:
                            sol_neon_ix_decoder.decode_failed_neon_tx_event_list()
                            # _LOG.debug("failed tx")
                            continue
                        sol_neon_ix_decoder.execute()
            self._complete_neon_block(dctx)
            await self._add_neon_block_to_queue(dctx)

        with logging_context(last_slot=f"{dctx.sol_commit[:3]}-{dctx.stop_slot}"):
            await self._save_checkpoint(dctx)

    async def run(self) -> None:
        await self._check_start_slot(self._db.get_min_used_slot())

        check_sec = float(self._cfg.indexer_check_msec) / 1000
        while not self._is_done_parsing:
            if not (await self._has_new_blocks()):
                await asyncio.sleep(check_sec)
                continue

            self._decoder_stat.start_timer()
            try:
                await self._process_solana_blocks()
            except BaseException as exc:
                _LOG.error("error on transactions decoding", exc_info=exc, extra=self._msg_filter)
            finally:
                self._decoder_stat.commit_timer()

        if self._db.is_reindexing_mode:
            done_stat = NeonDoneReindexStat(reindex_ident=self._db.reindex_ident)
            self._stat_client.commit_done_reindex_stat(done_stat)

    async def _has_new_blocks(self) -> bool:
        if self._db.is_reindexing_mode:
            # reindexing can't precede of indexing
            finalized_slot = await self._db.get_finalized_slot()
            # reindexing should stop on the terminated slot
            finalized_slot = min(self._term_slot + 100, finalized_slot)
            if result := self._last_processed_slot < finalized_slot:
                self._commit_progress_stat()
            self._last_finalized_slot = finalized_slot
        else:
            self._last_confirmed_slot = await self._sol_client.get_slot(SolCommit.Confirmed)
            if result := self._last_processed_slot != self._last_confirmed_slot:
                self._last_finalized_slot = await self._sol_client.get_slot(SolCommit.Finalized)
                if self._tracer_api_client:
                    self._last_tracer_slot = await self._tracer_api_client.get_max_slot()
                    # if no connection to the tracer db, but config has a delay,
                    #    limit indexing by finalized slot
                    if (self._last_tracer_slot is None) and self._cfg.slot_processing_delay:
                        self._last_confirmed_slot = self._last_finalized_slot
                self._commit_progress_stat()
        return result

    @property
    def _is_done_parsing(self) -> bool:
        """Stop parsing can happen only in reindexing mode"""
        if not self._db.is_reindexing_mode:
            return False

        if self._last_processed_slot < self._db.stop_slot:
            return False
        elif self._last_processed_slot >= self._term_slot:
            return True

        if not (neon_block := self._neon_block_dict.finalized_neon_block):
            return True

        neon_block.check_stuck_objs(self._cfg)
        return neon_block.min_slot > self._db.stop_slot

    async def _process_solana_blocks(self) -> None:
        dctx = SolNeonDecoderCtx(self._cfg, self._decoder_stat)
        try:
            await self._collect_neon_txs(dctx, self._last_finalized_slot, SolCommit.Finalized)
        except SolFailedHistoryError as exc:
            _LOG.warning(
                log_msg(
                    "block branch: {BlockBranch}, fail to parse finalized history: {Error}",
                    Error=str(exc),
                    BlockBranch=dctx,
                ),
                extra=self._msg_filter,
            )
            await self._check_start_slot(exc.slot)
            return
        except SolHistoryError as exc:
            _LOG.debug(
                log_msg(
                    "block branch: {BlockBranch}, skip parsing of finalized history: {Error}",
                    Error=str(exc),
                    BlockBranch=dctx,
                ),
                extra=self._msg_filter,
            )
            return

        # Don't parse not-finalized blocks on reindexing of old blocks
        if self._db.is_reindexing_mode or self._last_tracer_slot:
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_slot = await self._sol_client.get_slot(SolCommit.Finalized)
        if (finalized_slot - self._last_finalized_slot) >= 5:
            _LOG.debug(
                log_msg(
                    "skip parsing of not-finalized history: {FinalizedSlot} > {LastFinalizedSlot}",
                    FinalizedSlot=finalized_slot,
                    LastFinalizedSlot=self._last_finalized_slot,
                )
            )
            return

        try:
            await self._collect_neon_txs(dctx, self._last_confirmed_slot, SolCommit.Confirmed)
        except SolHistoryError as exc:
            # There are a lot of reason for skipping not-finalized history on live systems
            # so uncomment the debug message only if you need investigate the root cause
            _LOG.debug(
                log_msg("skip parsing of not-finalized history: {Error}", Error=str(exc)), extra=self._msg_filter
            )
            pass

    async def _check_start_slot(self, base_slot: int) -> None:
        block_finder = SolFirstBlockFinder(self._sol_client)
        first_slot = await block_finder.find_slot()

        if first_slot < base_slot:
            # if first available slot on Solana is less then the base slot,
            #   then find the first not-empty slot from the base_slot
            # it can happen if the Solana node has broken ledger
            first_slot = await SolNotEmptyBlockFinder(self._sol_client, start_slot=base_slot).find_slot()

        min_used_slot = self._db.get_min_used_slot()
        if min_used_slot < first_slot:
            _LOG.debug(
                log_msg(
                    "move the min used slot from {MinUsedSlot} to {FirstAvailableSlot}",
                    MinUsedSlot=min_used_slot,
                    FirstAvailableSlot=first_slot,
                )
            )
            await self._db.set_start_slot(first_slot)

        # Skip history if it was cleaned by the Solana node
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if (finalized_neon_block is not None) and (first_slot > finalized_neon_block.slot):
            self._neon_block_dict.clear()

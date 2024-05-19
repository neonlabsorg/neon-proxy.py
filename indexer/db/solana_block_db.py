from __future__ import annotations

import logging
from dataclasses import dataclass

from typing_extensions import Self

from common.config.constants import ONE_BLOCK_SEC
from common.db.db_connect import DbConnection, DbSql, DbSqlParam, DbTxCtx, DbQueryBody
from common.ethereum.commit_level import EthCommit
from common.ethereum.hash import EthBlockHash
from common.neon.block import NeonBlockHdrModel
from common.utils.format import hex_to_int
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolSlotRange:
    earliest_slot: int
    finalized_slot: int
    latest_slot: int


class SolBlockDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "solana_blocks", _Record, ("block_slot",))

        self._block_time_query = DbQueryBody()
        self._block_by_slot_query = DbQueryBody()
        self._block_by_hash_query = DbQueryBody()
        self._finalize_query = DbQueryBody()
        self._deactivate_query = DbQueryBody()
        self._activate_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        block_time_sql = DbSql(
            """
            (
            SELECT 
                a.block_slot AS prev_slot,
                a.block_time AS prev_block_time,
                NULL AS next_slot,
                NULL AS next_block_time
            FROM 
                {table_name} AS a
            WHERE 
                a.block_slot <= {slot}
            ORDER BY 
                a.block_slot DESC LIMIT 1
            )
            UNION DISTINCT
            (
            SELECT 
                NULL AS prev_slot,
                NULL AS prev_block_time,
                b.block_slot AS next_slot,
                b.block_time AS next_block_time
            FROM 
                {table_name} AS b
            WHERE 
                b.block_slot >= {slot}
            ORDER BY 
                b.block_slot LIMIT 1
            )
            """
        ).format(
            table_name=self._table_name,
            slot=DbSqlParam("slot"),
        )

        block_by_slot_sql = DbSql(
            """
            (
            SELECT 
                {column_list},
                b.block_hash AS parent_block_hash
            FROM 
                {table_name} AS a
            LEFT OUTER JOIN 
                {table_name} AS b
                ON b.block_slot = {slot} - 1
                AND b.is_active = True
            WHERE 
                a.block_slot = {slot}
                AND a.is_active = True
            LIMIT 1
            )
            UNION DISTINCT
            (
            SELECT 
                {column_list},
                b.block_hash AS parent_block_hash
            FROM 
                {table_name} AS b
            LEFT OUTER JOIN 
                {table_name} AS a
                ON a.block_slot = {slot}
                AND a.is_active = True
            WHERE 
                b.block_slot = {slot} - 1
                AND b.is_active = True
            LIMIT 1
            )
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            slot=DbSqlParam("slot"),
        )

        block_by_hash_sql = DbSql(
            """;
            SELECT 
                {column_list},
                b.block_hash AS parent_block_hash
            FROM 
                {table_name} AS a
            FULL OUTER JOIN 
                {table_name} AS b
                ON b.block_slot = a.block_slot - 1
                AND a.is_active = True
                AND b.is_active = True
            WHERE 
                a.block_hash = {block_hash}
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
            block_hash=DbSqlParam("block_hash"),
        )

        finalize_sql = DbSql(
            """;
            UPDATE 
                {table_name}
            SET 
                is_finalized = True,
                is_active = True
            WHERE 
                block_slot = ANY({slot_list})
            """
        ).format(
            table_name=self._table_name,
            slot_list=DbSqlParam("slot_list"),
        )

        deactivate_sql = DbSql(
            """;
            UPDATE 
                {table_name}
            SET 
                is_active = False
            WHERE 
                block_slot > {from_slot}
            """
        ).format(
            table_name=self._table_name,
            from_slot=DbSqlParam("from_slot"),
        )

        activate_sql = DbSql(
            """;
            UPDATE 
                {table_name}
            SET 
                is_active = True
            WHERE 
                block_slot = ANY({slot_list})
            """
        ).format(
            table_name=self._table_name,
            slot_list=DbSqlParam("slot_list"),
        )

        (
            self._block_time_query,
            self._block_by_slot_query,
            self._block_by_hash_query,
            self._finalize_query,
            self._deactivate_query,
            self._activate_query,
        ) = await self._db.sql_to_query(
            block_time_sql,
            block_by_slot_sql,
            block_by_hash_sql,
            finalize_sql,
            deactivate_sql,
            activate_sql,
        )

    @staticmethod
    def _generate_fake_block_hash(slot: int) -> str:
        if slot < 0:
            return "0x" + "00" * EthBlockHash.HashSize

        hex_num = hex(slot)[2:]
        num_len = len(hex_num)
        hex_num = "00" + hex_num.rjust(((num_len >> 1) + (num_len % 2)) << 1, "0")
        return "0x" + hex_num.rjust(EthBlockHash.HashSize * 2, "f")

    @classmethod
    def _check_block_hash(cls, slot: int, block_hash: str | None) -> str:
        return block_hash or cls._generate_fake_block_hash(slot)

    async def _generate_block_time(self, ctx: DbTxCtx, slot: int) -> int | None:
        # Search the nearest block before requested block
        rec = await self._fetch_one(ctx, self._block_time_query, _BySlot(slot), record_type=_BlockTime)
        if not rec:
            _LOG.warning("failed to get nearest blocks for block %s", slot)
            return None

        if rec.prev_block_time:
            return rec.prev_block_time + int((slot - rec.prev_slot) * ONE_BLOCK_SEC)
        return rec.next_block_time - int((rec.next_slot - slot) * ONE_BLOCK_SEC)

    @staticmethod
    def _get_fake_slot(hash_number: EthBlockHash) -> int | None:
        hash_number = hash_number.to_string()[2:].lstrip("f")
        if (len(hash_number) > 12) or (hash_number[:2] != "00"):
            return None

        if not (hex_number := hash_number.lstrip("0")):
            return 0
        return hex_to_int(hex_number)

    async def _generate_fake_block(self, ctx: DbTxCtx, slot: int | None, slot_range: SolSlotRange) -> NeonBlockHdrModel:
        if not slot:
            return NeonBlockHdrModel.new_empty(slot=0)

        if not (block_time := await self._generate_block_time(ctx, slot)):
            return NeonBlockHdrModel(slot=slot)

        is_finalized = slot <= slot_range.finalized_slot
        sol_commit = EthCommit.Finalized if is_finalized else EthCommit.Latest

        return NeonBlockHdrModel(
            slot=slot,
            commit=sol_commit,
            block_hash=self._generate_fake_block_hash(slot),
            block_time=block_time,
            parent_slot=slot-1,
            parent_block_hash=self._generate_fake_block_hash(slot - 1),
        )

    async def _block_from_value(
        self, ctx: DbTxCtx, slot: int | None, slot_range: SolSlotRange, rec: _RecordWithParent
    ) -> NeonBlockHdrModel:
        if not rec:
            return await self._generate_fake_block(ctx, slot, slot_range)

        slot = slot or rec.block_slot
        block_time = rec.block_time or await self._generate_block_time(ctx, slot)
        commit = EthCommit.Finalized if rec.is_finalized else EthCommit.Latest

        return NeonBlockHdrModel(
            slot=slot,
            commit=commit,
            block_hash=self._check_block_hash(slot, rec.block_hash),
            block_time=block_time,
            parent_slot=slot - 1,
            parent_block_hash=self._check_block_hash(slot - 1, rec.parent_block_hash),
        )

    async def get_block_by_slot(self, ctx: DbTxCtx, slot: int, slot_range: SolSlotRange) -> NeonBlockHdrModel:
        if slot > slot_range.latest_slot:
            return NeonBlockHdrModel.new_empty(slot=slot)

        elif slot < slot_range.earliest_slot:
            return await self._generate_fake_block(ctx, slot, slot_range)

        rec: _RecordWithParent = await self._fetch_one(
            ctx,
            self._block_by_slot_query,
            _BySlot(slot),
            record_type=_RecordWithParent,
        )
        return await self._block_from_value(ctx, slot, slot_range, rec)

    async def get_block_by_hash(
        self, ctx: DbTxCtx, block_hash: EthBlockHash, slot_range: SolSlotRange
    ) -> NeonBlockHdrModel:
        if (fake_slot := self._get_fake_slot(block_hash)) is not None:
            block = await self.get_block_by_slot(ctx, fake_slot, slot_range)
            kwargs = block.to_dict()
            kwargs.pop("block_hash")  # it can be a request from an uncle history branch
            return NeonBlockHdrModel(block_hash=block_hash, **kwargs)

        rec = await self._fetch_one(
            ctx,
            self._block_by_hash_query,
            _ByHash(block_hash.to_string()),
            record_type=_RecordWithParent,
        )
        return await self._block_from_value(ctx, None, slot_range, rec)

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [_Record.from_block_hdr(block.neon_block_hdr) for block in block_list]
        await self._insert_row_list(ctx, rec_list)

    async def finalize_block_list(self, ctx: DbTxCtx, from_slot: int, to_slot: int, slot_list: tuple[int, ...]) -> None:
        by_slot_range = _BySlotRange(from_slot, to_slot, list(slot_list))
        await self._update_row(ctx, self._finalize_query, by_slot_range)
        await self._update_row(ctx, self._clean_query, by_slot_range)

    async def activate_block_list(self, ctx: DbTxCtx, from_slot: int, slot_list: tuple[int, ...]) -> None:
        by_slot_range = _BySlotRange(from_slot, -1, list(slot_list))
        await self._update_row(ctx, self._deactivate_query, by_slot_range)
        await self._update_row(ctx, self._activate_query, by_slot_range)


@dataclass(frozen=True)
class _Record:
    block_slot: int
    block_hash: str
    block_time: int
    parent_block_slot: int
    is_finalized: bool
    is_active: bool

    @classmethod
    def from_block_hdr(cls, hdr: NeonBlockHdrModel) -> Self:
        return cls(
            block_slot=hdr.slot,
            block_hash=hdr.block_hash.to_string(),
            block_time=hdr.block_time,
            parent_block_slot=hdr.parent_slot,
            is_finalized=hdr.is_finalized,
            is_active=hdr.is_finalized,
        )


@dataclass(frozen=True)
class _RecordWithParent(_Record):
    parent_block_hash: str


@dataclass(frozen=True)
class _BlockTime:
    prev_slot: int | None
    prev_block_time: int | None
    next_slot: int | None
    next_block_time: int | None


@dataclass(frozen=True)
class _BySlot:
    slot: int


@dataclass(frozen=True)
class _ByHash:
    block_hash: str


@dataclass(frozen=True)
class _BySlotRange:
    from_slot: int
    to_slot: int
    slot_list: list[int]

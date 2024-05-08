from __future__ import annotations

from dataclasses import dataclass

from common.db.base_db_table import BaseDbTable
from common.db.db_connect import DbQueryBody, DbSql, DbTxCtx, DbConnection, DbSqlParam
from common.utils.pydantic import RootModel
from .objects import NeonIndexedBlockInfo


class StuckDBTable(BaseDbTable):
    def __init__(self, db: DbConnection, table_name: str, *, has_finalized: bool = False) -> None:
        record_type = _RecordWithFinalized if has_finalized else _Record
        key_list = ("block_slot", "is_finalized") if has_finalized else ("block_slot",)
        super().__init__(db, table_name, record_type, key_list)

        self._has_finalized = has_finalized
        self._select_query = DbQueryBody()
        self._delete_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        select_sql = DbSql(
            """;
            SELECT 
                {column_list}
            FROM 
                {table_name} AS a
            """
        ).format(
            column_list=self._column_list,
            table_name=self._table_name,
        )
        if self._has_finalized:
            select_sql += DbSql(" WHERE a.is_finalized = {}").format(DbSqlParam("is_finalized"))
        select_sql += DbSql(" ORDER BY a.block_slot DESC")

        delete_sql = DbSql(
            """;
            DELETE FROM 
                {table_name} AS a
            """
        ).format(
            table_name=self._table_name,
        )
        if self._has_finalized:
            delete_sql += DbSql(" WHERE a.is_finalized = {}").format(DbSqlParam("is_finalized"))

        self._select_query, self._delete_query = await self._db.sql_to_query(select_sql, delete_sql)

    async def _set_obj_list(self, ctx: DbTxCtx, neon_block: NeonIndexedBlockInfo, obj_list: tuple[dict, ...]) -> None:
        await self._update_row(ctx, self._delete_query, _ByFinalized(neon_block.is_finalized))

        if not obj_list:
            return

        json_data = _ObjDictList(root=obj_list).to_json()
        await self._insert_row(ctx, _RecordWithFinalized(neon_block.stuck_slot, json_data, neon_block.is_finalized))

    async def get_obj_list(self, ctx: DbTxCtx, is_finalized: bool) -> tuple[int | None, tuple[dict, ...]]:
        rec = await self._fetch_one(ctx, self._select_query, _ByFinalized(is_finalized))
        if not rec:
            return None, tuple()

        neon_tx_list = _ObjDictList.from_json(rec.json_data_list).root
        return rec.block_slot, tuple(neon_tx_list)


class _ObjDictList(RootModel):
    root: tuple[dict, ...]


@dataclass(frozen=True)
class _ByFinalized:
    is_finalized: bool


@dataclass(frozen=True)
class _Record:
    block_slot: int
    json_data_list: str


@dataclass(frozen=True)
class _RecordWithFinalized(_Record):
    is_finalized: bool

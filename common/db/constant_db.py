from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from .base_db_table import BaseDbTable
from .db_connect import DbConnection, DbTxCtx, DbSql, DbSqlParam, DbQueryBody

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Record:
    key: str
    value: bytes


@dataclass(frozen=True)
class _ByKey:
    key: list[str]


class ConstantDb(BaseDbTable):
    def __init__(self, db_conn: DbConnection):
        super().__init__(db_conn, "constants", _Record, ("key",))

        self._key_list_query = DbQueryBody()
        self._get_query = DbQueryBody()
        self._del_query = DbQueryBody()
        self._full_list_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()

        key_list_sql = DbSql(";SELECT {column_list} FROM {table_name} AS a").format(
            table_name=self._table_name, column_list=self._column_list
        )

        get_sql = DbSql(";SELECT {column_list} FROM {table_name} AS a WHERE key = ANY({key})").format(
            table_name=self._table_name, column_list=self._column_list, key=DbSqlParam("key")
        )

        del_sql = DbSql(";DELETE FROM {table_name} WHERE key = ANY({key})").format(
            table_name=self._table_name, key=DbSqlParam("key")
        )
        full_list_sql = DbSql(";SELECT {column_list} FROM {table_name} AS a").format(
            table_name=self._table_name, column_list=self._column_list
        )

        (
            self._key_list_query,
            self._get_query,
            self._del_query,
            self._full_list_query,
        ) = await self._db.sql_to_query(
            key_list_sql,
            get_sql,
            del_sql,
            full_list_sql,
        )

    async def get_key_list(self, ctx: DbTxCtx) -> tuple[str, ...]:
        rec_list: list[_Record] = await self._fetch_all(ctx, self._key_list_query, None)
        return tuple([rec.key for rec in rec_list])

    async def get_int(self, ctx: DbTxCtx, key: str, default: int) -> int:
        if not (rec := await self._fetch_one(ctx, self._get_query, _ByKey([key]))):
            return default
        return int(rec.value, 10)

    async def get_int_list(self, ctx, key_list: Sequence[str], default: int) -> tuple[int, ...]:
        value_dict: dict[str, int] = {key: default for key in key_list}
        rec_list = await self._fetch_all(ctx, self._get_query, _ByKey(list(key_list)))
        for rec in rec_list:
            value_dict[rec.key] = int(rec.value, 10)
        return tuple(list(value_dict.values()))

    async def get_str(self, ctx: DbTxCtx, key: str, default: str) -> str:
        if not (rec := await self._fetch_one(ctx, self._get_query, _ByKey([key]))):
            return default
        return str(rec.value, "utf-8")

    async def set(self, ctx: DbTxCtx, key: str, value: str | int) -> None:
        value = str(value) if isinstance(value, int) else value
        await self._insert_row(ctx, _Record(key, bytes(value, "utf-8")))

    async def delete_list(self, ctx: DbTxCtx, key_list: Sequence[str]) -> None:
        await self._update_row(ctx, self._del_query, _ByKey(list(key_list)))

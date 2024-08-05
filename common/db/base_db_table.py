from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .db_connect import (
    DbConnection,
    DbTxCtx,
    DbQuery,
    DbParamCont,
    DbSql,
    DbSqlIdent,
    DbSqlParam,
    DbRecordType,
    DbQueryBody,
)

_LOG = logging.getLogger(__name__)


class BaseDbTable:
    def __init__(
        self,
        db: DbConnection,
        table_name: str,
        record_type: DbRecordType,
        key_list: tuple[str, ...],
    ):
        self._db = db
        self._raw_table_name = table_name
        self._table_name = DbSqlIdent(table_name)
        self._block_table_name = DbSqlIdent("solana_blocks")
        self._cost_table_name = DbSqlIdent("solana_transaction_costs")

        column_list = tuple([field.name for field in dataclasses.fields(record_type)])

        for key in key_list:
            assert key in column_list
        assert len(set(key_list)) == len(key_list)

        self._raw_column_list = column_list
        self._raw_key_list = key_list

        self._RecordType = record_type
        self._column_list = DbSql(", ").join(DbSql("{}.{}").format(DbSqlIdent("a"), DbSqlIdent(c)) for c in column_list)
        self._value_list = DbSql(", ").join(map(DbSqlParam, column_list))
        self._key_list = DbSql(", ").join(map(DbSqlIdent, key_list))
        self._insert_row_query = DbQueryBody()

    async def start(self) -> None:
        """
        The building of queries requires a connection, which can be requested only in async mode.
        In this function DbTable converts DbSql -> bytes, to exclude this process on each query execution.
        """
        if 0 < len(self._raw_key_list) < len(self._raw_column_list):
            update_list = [DbSql("{c}=EXCLUDED.{c}").format(c=DbSqlIdent(c)) for c in self._raw_column_list]
            key_sql = DbSql("({key_list}) DO UPDATE SET ").format(key_list=self._key_list)
            update_sql = key_sql + DbSql(", ").join(update_list)
        else:
            update_sql = DbSql(" DO NOTHING")

        insert_row_sql = DbSql(";INSERT INTO {table_name} ({column_list}) VALUES ({value_list}) ON CONFLICT").format(
            table_name=self._table_name,
            column_list=DbSql(", ").join(map(DbSqlIdent, self._raw_column_list)),
            value_list=self._value_list,
        )
        insert_row_sql += update_sql

        self._insert_row_query = await self._db.sql_to_query(insert_row_sql)

    async def stop(self) -> None:
        pass

    async def _insert_row(self, ctx: DbTxCtx, record: DbRecordType | dict) -> None:
        await self._db.update_row(ctx, self._raw_table_name, self._insert_row_query, self._as_param_cont(record))

    async def _update_row(self, ctx: DbTxCtx, update_row_request: DbQuery, record: DbRecordType | dict | None) -> None:
        await self._db.update_row(ctx, self._raw_table_name, update_row_request, self._as_param_cont(record))

    def _record_to_row_list(self, record_list: Sequence[DbRecordType | dict]) -> list[DbParamCont]:
        key_set: set[str] = set()
        row_list: list[DbParamCont] = list()
        for rec in record_list:
            row = self._as_param_cont(rec)
            key = ":".join(str(row[k]) for k in self._raw_key_list)
            if key in key_set:
                continue

            key_set.add(key)
            row_list.append(row)
        return row_list

    async def _insert_row_list(self, ctx: DbTxCtx, record_list: Sequence[DbRecordType | dict]) -> None:
        if not record_list:
            return

        row_list = self._record_to_row_list(record_list)
        await self._db.update_row_list(ctx, self._raw_table_name, self._insert_row_query, row_list)

    async def _fetch_one(
        self,
        ctx: DbTxCtx,
        query: DbQuery,
        param_cont: DbRecordType | dict | None,
        *,
        record_type: DbRecordType | None = None,
    ):
        return await self._db.fetch_one(
            ctx,
            self._raw_table_name,
            record_type or self._RecordType,
            query,
            self._as_param_cont(param_cont),
        )

    async def _fetch_all(
        self,
        ctx: DbTxCtx,
        query: DbQuery,
        param_cont: DbRecordType | dict | None,
        *,
        record_type: DbRecordType | None = None,
    ) -> list:
        result_list = await self._db.fetch_many(
            ctx,
            self._raw_table_name,
            record_type or self._RecordType,
            10000,
            query,
            self._as_param_cont(param_cont),
        )
        return result_list if result_list else list()

    @staticmethod
    def _as_param_cont(record: DbRecordType | dict | None) -> DbParamCont:
        if not record:
            return dict()
        if isinstance(record, dict):
            return record
        return dataclasses.asdict(record)

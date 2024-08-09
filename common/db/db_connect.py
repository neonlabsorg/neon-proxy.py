from __future__ import annotations

import asyncio
import itertools
import logging
from dataclasses import dataclass
from typing import Callable, Union, Sequence, Final

import psycopg as _pg
import psycopg.abc as _abc
import psycopg.rows as _rows
import psycopg.sql as _sql
import psycopg_pool as _pg_pool

from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..stat.client_rpc import RpcStatInfo, RpcStatClient
from ..utils.json_logger import log_msg

_LOG = logging.getLogger(__name__)
_PgAsyncConnPool = _pg_pool.AsyncConnectionPool
_PgAsyncConn = _pg.AsyncConnection

DbSql = _sql.SQL
DbSqlComposable = _sql.Composable
DbSqlIdent = _sql.Identifier
DbSqlParam = _sql.Placeholder
DbQuery = _abc.Query
DbQueryBody = bytes
DbParamCont = _abc.Params
DbRecordType = type[dataclass]


class DbConnection:
    _stat_name: Final[str] = "PostgreSQL"

    def __init__(self, cfg: Config, stat_client: RpcStatClient) -> None:
        cfg.validate_db_config()
        self._cfg = cfg
        self._stat_client = stat_client
        self._msg_filter = LogMsgFilter(cfg)
        self._conn_pool: _PgAsyncConnPool | None = None
        self._debug_query = False

    def enable_debug_query(self):
        self._debug_query = True

    async def start(self) -> None:
        connect_param_dict = dict(
            dbname=self._cfg.pg_db,
            user=self._cfg.pg_user,
            password=self._cfg.pg_password,
            host=self._cfg.pg_host,
        )

        if self._cfg.pg_timeout_sec > 0:
            def_timeout_sec = self._cfg.pg_timeout_sec
            wait_ms = self._cfg.pg_timeout_sec * 1000
            connect_param_dict["options"] = f"-c lock_timeout={wait_ms} "
        else:
            def_timeout_sec = 15.0

        self._conn_pool = _PgAsyncConnPool(
            kwargs=connect_param_dict,
            check=_PgAsyncConnPool.check_connection,
            timeout=def_timeout_sec,
            reconnect_timeout=def_timeout_sec,
            max_lifetime=(10 * 60),  # 10 minutes
            min_size=5,
            max_size=self._cfg.pg_conn_cnt,
            open=False,
        )
        await self._conn_pool.open()
        await self._conn_pool.wait()

    async def stop(self) -> None:
        pass

    async def sql_to_query(self, *sql) -> DbQueryBody | tuple[DbQueryBody, ...]:
        """
        Combine all parts of SQL into one bytes-string.
        It happens each time in the cursor.execute(), so the function is used to decrease the time of the execution.
        At the same time, SQLs with big size can be skipped for caching for preparation, that is why the function
        removes surplus spaces, tabs and \r\n, and ; at the end and start
        """
        sql_list = list(sql)

        async with self._conn_pool.connection(None) as conn:
            query_list = tuple([self._sql_to_query(conn, s) for s in sql_list])

        if self._debug_query:
            for query in query_list:
                _LOG.debug(log_msg("compile sql: {Sql}", Sql=str(query, "utf-8").replace('"', "")))

        if len(sql_list) == 1:
            return query_list[0]
        return query_list

    @staticmethod
    def _sql_to_query(conn: _PgAsyncConn, sql: DbQuery | DbSqlComposable) -> bytes:
        if isinstance(sql, bytes):
            return sql
        elif isinstance(sql, DbSqlComposable):
            return b" ".join(sql.as_bytes(conn).split()).strip(b"; ")
        return sql.encode("utf-8")

    async def run_tx(self, action: Callable) -> None:
        for retry in itertools.count():
            try:
                async with self._conn_pool.connection(None) as conn:
                    async with conn.transaction():
                        return await action(_DbTxCtx(conn))
            except BaseException as exc:
                await self._on_fail_execute(retry, exc)

    async def update_row(self, ctx: DbTxCtx, table_name: str, query: DbQuery, row: DbParamCont) -> None:
        async def _action(conn: _PgAsyncConn) -> None:
            await conn.execute(self._sql_to_query(conn, query), row)

        await self._exec_action(ctx, table_name, True, _action)

    async def update_row_list(
        self,
        ctx: DbTxCtx,
        table_name: str,
        query: DbQuery,
        row_list: Sequence[DbParamCont],
    ) -> None:
        async def _action(conn: _PgAsyncConn) -> None:
            async with conn.cursor() as cursor:
                await cursor.executemany(self._sql_to_query(conn, query), row_list)

        await self._exec_action(ctx, table_name, True, _action)

    async def fetch_one(
        self,
        ctx: DbTxCtx,
        table_name: str,
        record_type: DbRecordType,
        query: DbQuery,
        param_list: DbParamCont,
    ) -> DbRecordType:
        async def _action(conn: _PgAsyncConn) -> record_type:
            async with conn.cursor(row_factory=_rows.class_row(record_type)) as cursor:
                await cursor.execute(self._sql_to_query(conn, query), param_list)
                return await cursor.fetchone()

        return await self._exec_action(ctx, table_name, False, _action)

    async def fetch_many(
        self,
        ctx: DbTxCtx,
        table_name: str,
        record_type: DbRecordType,
        size: int,
        query: DbQuery,
        param_list: DbParamCont,
    ) -> list[DbRecordType]:
        async def _action(conn: _PgAsyncConn) -> list[DbRecordType]:
            async with conn.cursor(row_factory=_rows.class_row(record_type)) as cursor:
                await cursor.execute(self._sql_to_query(conn, query), param_list)
                return await cursor.fetchmany(size)

        return await self._exec_action(ctx, table_name, False, _action)

    async def _exec_action(self, ctx: DbTxCtx, table_name: str, is_modification: bool, action: Callable):
        stat = RpcStatInfo.from_raw(
            stat_client=self._stat_client,
            stat_name=self._stat_name,
            method=table_name,
            is_modification=is_modification,
        )
        with stat:
            for retry in itertools.count():
                try:
                    if ctx:
                        return await action(ctx.conn)

                    stat.start_timer()
                    async with self._conn_pool.connection(None) as conn:
                        return await action(conn)
                except BaseException as exc:
                    if ctx:
                        # Got an exception during the DB-tx execution, catch of exception occurs inside run_tx()
                        raise
                    await self._on_fail_execute(retry, exc)

                    # if there were no re-raises, commit the current error
                    stat.commit_stat(is_error=True)
                    await asyncio.sleep(0.2)

    async def _on_fail_execute(self, retry: int, exc: BaseException) -> None:
        if isinstance(exc, _pg_pool.PoolClosed):
            _LOG.warning(
                log_msg("PoolClosed error on {Retry} try to execute query on DB connection", Retry=retry),
                exc_info=exc,
                extra=self._msg_filter,
            )
            raise
        elif isinstance(exc, (_pg.OperationalError, _pg.InterfaceError)):
            if retry > 1:
                _LOG.warning(
                    log_msg(
                        "error on {Retry} try to execute query on DB connection: {Error}",
                        Retry=retry,
                        Error=str(exc),
                    ),
                    extra=self._msg_filter,
                )
        else:
            _LOG.error(
                log_msg("unexpected error on {Retry} try to execute query on DB connection", Retry=retry),
                exc_info=exc,
                extra=self._msg_filter,
            )
            raise


@dataclass(frozen=True)
class _DbTxCtx:
    conn: _PgAsyncConn


DbTxCtx = Union[_DbTxCtx, None]

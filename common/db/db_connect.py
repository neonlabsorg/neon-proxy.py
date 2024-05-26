from __future__ import annotations

import asyncio
import contextlib
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
    def __init__(self, cfg: Config):
        cfg.validate_db_config()
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(cfg)
        self._conn_pool: _PgAsyncConnPool | None = None
        self._is_stopped = True
        self._is_connected = False
        self._debug_query = False
        self._is_close_conn_event = asyncio.Event()
        self._is_connected_task: asyncio.Task | None = None

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

        self._is_stopped = False
        self._is_connected = True
        self._is_connected_task = asyncio.get_event_loop().create_task(self._is_connected_loop())

    async def stop(self) -> None:
        self._is_stopped = True
        self._is_close_conn_event.set()
        await self._is_connected_task
        await self._conn_pool.close()

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

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    async def _is_connected_loop(self) -> None:
        loop = asyncio.get_event_loop()
        conn_fileno: int | None = None
        sleep_sec: Final[float] = 60.0

        while not self._is_stopped:
            try:
                async with self._conn_pool.connection(None) as conn:
                    self._is_close_conn_event.clear()
                    conn_fileno = conn.fileno()
                    loop.add_reader(conn_fileno, self._is_close_conn_event.set)

                    while not self._is_close_conn_event.is_set():
                        with contextlib.suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(self._is_close_conn_event.wait(), sleep_sec)

                        # No FD activity detected in sleep_sec seconds -> force to check the DB connection
                        if not self._is_close_conn_event.is_set():
                            await self._conn_pool.check_connection(conn)

            except (_pg.OperationalError, _pg.InterfaceError):
                pass  # normal error on checking DB connection - it is closed

            except BaseException as exc:
                _LOG.error("unexpected error on waiting event from DB", extra=self._msg_filter, exc_info=exc)

            finally:
                if not self._is_stopped:
                    _LOG.debug("lost db connection ...")

                self._is_connected = False
                if conn_fileno is not None:
                    loop.remove_reader(conn_fileno)
                conn_fileno = None

            if self._is_stopped:
                continue

            try:
                await self._conn_pool.check()
                self._is_connected = self._conn_pool.get_stats()["pool_available"] > 0
            except BaseException as exc:
                _LOG.error("unexpected error on checking DB connections", extra=self._msg_filter, exc_info=exc)

    async def run_tx(self, action: Callable) -> None:
        for retry in itertools.count():
            try:
                async with self._conn_pool.connection(None) as conn:
                    async with conn.transaction():
                        return await action(_DbTxCtx(conn))
            except BaseException as exc:
                await self._on_fail_execute(retry, exc)

    async def update_row(self, ctx: DbTxCtx, query: DbQuery, row: DbParamCont) -> None:
        async def _action(conn: _PgAsyncConn) -> None:
            await conn.execute(self._sql_to_query(conn, query), row)

        await self._exec_action(ctx, _action)

    async def update_row_list(self, ctx: DbTxCtx, query: DbQuery, row_list: Sequence[DbParamCont]) -> None:
        async def _action(conn: _PgAsyncConn) -> None:
            async with conn.cursor() as cursor:
                await cursor.executemany(self._sql_to_query(conn, query), row_list)

        await self._exec_action(ctx, _action)

    async def fetch_one(
        self, ctx: DbTxCtx, record_type: DbRecordType, query: DbQuery, param_list: DbParamCont
    ) -> DbRecordType:
        async def _action(conn: _PgAsyncConn) -> record_type:
            async with conn.cursor(row_factory=_rows.class_row(record_type)) as cursor:
                await cursor.execute(self._sql_to_query(conn, query), param_list)
                return await cursor.fetchone()

        return await self._exec_action(ctx, _action)

    async def fetch_many(
        self, ctx: DbTxCtx, record_type: DbRecordType, size: int, query: DbQuery, param_list: DbParamCont
    ) -> list[DbRecordType]:
        async def _action(conn: _PgAsyncConn) -> list[DbRecordType]:
            async with conn.cursor(row_factory=_rows.class_row(record_type)) as cursor:
                await cursor.execute(self._sql_to_query(conn, query), param_list)
                return await cursor.fetchmany(size)

        return await self._exec_action(ctx, _action)

    async def _exec_action(self, ctx: DbTxCtx, action: Callable):
        for retry in itertools.count():
            try:
                if ctx:
                    return await action(ctx.conn)

                async with self._conn_pool.connection(None) as conn:
                    return await action(conn)
            except BaseException as exc:
                if ctx:
                    # Got an exception during the DB-tx execution, catch of exception occurs inside run_tx()
                    raise
                await self._on_fail_execute(retry, exc)

    async def _on_fail_execute(self, retry: int, exc: BaseException) -> None:
        if isinstance(exc, (_pg.OperationalError, _pg.InterfaceError)):
            if retry > 1:
                _LOG.warning(
                    log_msg(
                        "error on {Retry} try to execute query on DB connection: {Error}",
                        Retry=retry,
                        Error=str(exc),
                    ),
                    extra=self._msg_filter,
                )
            await asyncio.sleep(0.2)
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

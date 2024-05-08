from dataclasses import dataclass

from common.db.base_db_table import BaseDbTable
from common.db.db_connect import DbQueryBody, DbSqlParam, DbSql, DbTxCtx


@dataclass(frozen=True)
class _BySlotRange:
    from_slot: int
    to_slot: int
    slot_list: list[int]


class HistoryDbTable(BaseDbTable):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._clean_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()
        clean_sql = DbSql(
            """;
            DELETE FROM 
              {table_name} 
            WHERE block_slot > {from_slot}
              AND block_slot <= {to_slot}
              AND block_slot <> ALL({slot_list})
            """
        ).format(
            table_name=self._table_name,
            from_slot=DbSqlParam("from_slot"),
            to_slot=DbSqlParam("to_slot"),
            slot_list=DbSqlParam("slot_list"),
        )
        self._clean_query = await self._db.sql_to_query(clean_sql)

    async def finalize_block_list(self, ctx: DbTxCtx, from_slot: int, to_slot: int, slot_list: tuple[int, ...]) -> None:
        await self._update_row(ctx, self._clean_query, _BySlotRange(from_slot, to_slot, list(slot_list)))

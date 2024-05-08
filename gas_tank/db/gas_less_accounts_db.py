from __future__ import annotations

from dataclasses import dataclass

from common.db.base_db_table import BaseDbTable
from common.db.db_connect import DbConnection, DbSql, DbSqlParam, DbQueryBody
from common.ethereum.hash import EthAddress


class GasLessAccountDb(BaseDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(
            db,
            "gas_less_accounts",
            _Record,
            ("address", "contract", "nonce"),
        )
        self._select_query = DbQueryBody()

    async def start(self) -> None:
        await super().start()
        select_sql = DbSql(
            """;
            SELECT 
                {column_list}
            FROM 
                {table_name} AS a
            WHERE 
                a.address = {address}
                AND a.nonce >= {nonce}
                AND a.nonce_done <= {nonce}
                AND a.gas_limit >= {gas_limit}
            ORDER BY 
                a.nonce, a.contract
            """
        ).format(
            table_name=self._table_name,
            column_list=self._column_list,
            address=DbSqlParam("address"),
            nonce=DbSqlParam("nonce"),
            gas_limit=DbSqlParam("gas_limit"),
        )
        self._select_query = await self._db.sql_to_query(select_sql)

    async def has_fee_less_tx_permit(
        self,
        address: EthAddress,
        contract: EthAddress,
        nonce: int,
        gas_limit: int,
    ) -> bool:
        rec_list = await self._fetch_all(
            None,
            self._select_query,
            _ByAddressNonce(address.to_string(), nonce, gas_limit),
        )
        for rec in rec_list:
            if contract is None:
                return True
            elif contract == (rec.contract or contract):
                return True
        return False


@dataclass(frozen=True)
class _Record:
    address: str
    contract: str | None
    nonce: int
    nonce_done: int
    gas_limit: int
    block_slot: int
    neon_sig: str


@dataclass(frozen=True)
class _ByAddressNonce:
    address: str
    nonce: int
    gas_limit: int

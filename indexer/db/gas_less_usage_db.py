from dataclasses import dataclass

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedTxInfo


class GasLessUsageDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "gas_less_usages", _Record, ("neon_sig",))

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [
            _Record.from_tx(tx)
            for block in block_list
            for tx in block.iter_done_neon_tx()
            if tx.neon_tx.gas_price == 0
        ]
        await self._insert_row_list(ctx, rec_list)


@dataclass(frozen=True)
class _Record:
    address: str
    block_slot: int
    neon_sig: str
    nonce: int
    to_addr: str
    operator: str
    neon_total_gas_usage: int

    @classmethod
    def from_tx(cls, tx: NeonIndexedTxInfo) -> Self:
        return cls(
            address=tx.neon_tx.from_address.to_string(),
            block_slot=tx.neon_tx_rcpt.slot,
            neon_sig=tx.neon_tx_hash.to_string(),
            nonce=tx.neon_tx.nonce,
            to_addr=tx.neon_tx.to_address.to_string(),
            operator=tx.operator.to_string(),
            neon_total_gas_usage=tx.total_gas_used,
        )

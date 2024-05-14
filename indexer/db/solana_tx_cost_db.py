from dataclasses import dataclass

from typing_extensions import Self

from common.db.db_connect import DbConnection, DbTxCtx
from common.solana.transaction_decoder import SolTxCostModel
from ..base.history_db import HistoryDbTable
from ..base.objects import NeonIndexedBlockInfo


class SolTxCostDb(HistoryDbTable):
    def __init__(self, db: DbConnection):
        super().__init__(db, "solana_transaction_costs", _Record, ("sol_sig", "block_slot"))

    async def set_block_list(self, ctx: DbTxCtx, block_list: tuple[NeonIndexedBlockInfo, ...]) -> None:
        rec_list = [_Record.from_sol_cost(sol_cost) for block in block_list for sol_cost in block.iter_sol_tx_cost()]
        await self._insert_row_list(ctx, rec_list)


@dataclass(frozen=True)
class _Record:
    sol_sig: str
    block_slot: int
    operator: str
    sol_spent: int

    @classmethod
    def from_sol_cost(cls, sol_cost: SolTxCostModel) -> Self:
        return cls(
            sol_sig=sol_cost.sol_tx_sig.to_string(),
            block_slot=sol_cost.slot,
            operator=sol_cost.sol_signer.to_string(),
            sol_spent=sol_cost.sol_expense,
        )

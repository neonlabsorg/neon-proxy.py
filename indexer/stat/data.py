from __future__ import annotations

from decimal import Decimal

from common.utils.pydantic import BaseModel


class NeonTxStat(BaseModel):
    tx_type: str
    token_name: str
    completed_neon_tx_cnt: int
    canceled_neon_tx_cnt: int
    sol_tx_cnt: int
    sol_spent: int
    token_income: int
    neon_step_cnt_limit: int
    cu_limit: int

    op_sol_spent: int
    op_token_income: int
    op_completed_neon_tx_cnt: int
    op_canceled_neon_tx_cnt: int


class NeonBlockStat(BaseModel):
    reindex_ident: str
    start_block: int
    parsed_block: int
    stop_block: int
    term_block: int
    finalized_block: int
    confirmed_block: int
    tracer_block: int | None


class NeonDoneBlockStat(BaseModel):
    reindex_ident: str
    parsed_block: int

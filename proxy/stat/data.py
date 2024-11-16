from __future__ import annotations

from common.utils.pydantic import BaseModel


class TokenGasPriceStat(BaseModel):
    token_name: str
    min_gas_price: int
    sol_price_usd: int
    token_price_usd: int


class TxPoolStat(BaseModel):
    mempool_len: int = 0
    process_queue_len: int = 0
    stuck_queue_len: int = 0
    process_stuck_queue_len: int = 0


class OpResourceStat(BaseModel):
    secret_cnt: int
    total_resource_cnt: int
    free_resource_cnt: int
    used_resource_cnt: int
    disabled_resource_cnt: int

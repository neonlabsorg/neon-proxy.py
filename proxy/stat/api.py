from dataclasses import dataclass

from typing_extensions import TypedDict

from common.utils.pydantic import BaseModel

STATISTIC_ENDPOINT = "/api/v1/statistic/"


class TxDoneData(BaseModel):
    time_nsec: int


class TxFailData(BaseModel):
    time_nsec: int


class TxTokenPoolData(BaseModel):
    token: str
    queue_len: int


class TxPoolData(BaseModel):
    scheduling_queue: list[TxTokenPoolData] = 0
    processing_queue_len: int = 0
    stuck_queue_len: int = 0
    processing_stuck_queue_len: int = 0



# class TokenGasPriceStat(BaseModel):
#     token_name: str
#     min_gas_price: int
#     token_price_usd: int
#
#
# class OpResourceStat(BaseModel):
#     secret_cnt: int
#     total_resource_cnt: int
#     free_resource_cnt: int
#     used_resource_cnt: int
#     disabled_resource_cnt: int

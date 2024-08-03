from common.ethereum.hash import EthAddressField
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import BaseModel, HexUIntField

STATISTIC_ENDPOINT = "/api/v1/statistic/"


class OpEarnedTokenBalanceData(BaseModel):
    token_name: str
    eth_address: EthAddressField
    balance: HexUIntField


class OpResourceHolderStatusData(BaseModel):
    owner: SolPubKeyField
    free_holder_cnt: int
    used_holder_cnt: int
    disabled_holder_cnt: int
    blocked_holder_cnt: int


class OpExecTokenBalanceData(BaseModel):
    owner: SolPubKeyField
    balance: int


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

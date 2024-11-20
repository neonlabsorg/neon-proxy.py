from __future__ import annotations

from enum import IntEnum
from typing import Annotated

from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from common.ethereum.hash import EthTxHashField
from common.neon.account import NeonAccount
from common.solana.alt_program import SolAltID
from common.utils.cached import cached_property
from common.utils.pydantic import BaseModel
from .mp_api import MpTxModel, MpStuckTxModel, MpTokenGasPriceModel, MpGasPriceModel

EXECUTOR_ENDPOINT = "/api/v1/executor/"


class ExecTokenModel(BaseModel):
    chain_id: int
    simple_cu_price: int
    profitable_gas_price: int
    pct_gas_price: int

    @classmethod
    def from_raw(cls, gas_price: MpGasPriceModel, token: MpTokenGasPriceModel) -> Self:
        return cls(
            chain_id=token.chain_id,
            simple_cu_price=gas_price.simple_cu_price,
            profitable_gas_price=token.profitable_gas_price,
            pct_gas_price=token.pct_gas_price,
        )


class ExecTxRequest(BaseModel):
    tx: MpTxModel
    token: ExecTokenModel

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.tx.tx_id)

    @cached_property
    def sender(self) -> NeonAccount:
        return NeonAccount.from_raw(self.tx.sender, self.token.chain_id)


class ExecStuckTxRequest(BaseModel):
    stuck_tx: MpStuckTxModel
    token: ExecTokenModel

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.stuck_tx.tx_id, is_stuck=True)


class ExecTxRespCode(IntEnum):
    Done = 1
    Failed = 2
    NonceTooLow = 3
    NonceTooHigh = 4


ExecTxRespCodeField = Annotated[
    ExecTxRespCode,
    PlainValidator(lambda v: ExecTxRespCode(v)),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class ExecTxResp(BaseModel):
    code: ExecTxRespCodeField
    state_tx_cnt: int = 0


class NeonAltModel(BaseModel):
    neon_tx_hash: EthTxHashField
    sol_alt_id: SolAltID


class DestroyAltListRequest(BaseModel):
    req_id: dict
    alt_list: list[NeonAltModel]


class DestroyAltListResp(BaseModel):
    result: bool

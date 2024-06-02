from __future__ import annotations

from enum import IntEnum
from typing import Annotated

from pydantic import PlainValidator, PlainSerializer

from common.ethereum.hash import EthTxHashField
from common.solana.alt_program import SolAltID
from common.utils.pydantic import BaseModel
from .mp_api import MpTxModel, MpStuckTxModel
from .op_api import OpResourceModel

EXECUTOR_ENDPOINT = "/api/v1/executor/"


class ExecTxRequest(BaseModel):
    tx: MpTxModel
    resource: OpResourceModel


class ExecStuckTxRequest(BaseModel):
    stuck_tx: MpStuckTxModel
    resource: OpResourceModel


class ExecTxRespCode(IntEnum):
    Done = 0
    Failed = 1
    BadResource = 2
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
    chain_id: int | None = None


class NeonAltModel(BaseModel):
    neon_tx_hash: EthTxHashField
    sol_alt_id: SolAltID


class DestroyAltListRequest(BaseModel):
    req_id: dict
    alt_list: list[NeonAltModel]


class DestroyAltListResp(BaseModel):
    result: bool

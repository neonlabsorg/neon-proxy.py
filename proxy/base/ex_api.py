from __future__ import annotations

from enum import IntEnum
from typing import Annotated, Self

from pydantic import PlainValidator, PlainSerializer

from common.ethereum.hash import EthTxHashField
from common.neon.address import NeonAddress, NeonAddressField
from common.solana.alt_program import SolAltID
from common.solana.pubkey import SolPubKeyField
from common.utils.cached import cached_property
from common.utils.pydantic import BaseModel
from .mp_api import MpTxModel, MpStuckTxModel, MpTokenGasPriceModel, MpGasPriceModel

EXECUTOR_ENDPOINT = "/api/v1/executor/"


class ExecTokenModel(BaseModel):
    chain_id: int
    simple_cu_price: int
    profitable_gas_price: int

    @classmethod
    def from_raw(cls, gas_price: MpGasPriceModel, token: MpTokenGasPriceModel) -> Self:
        return cls(
            chain_id=token.chain_id,
            simple_cu_price=gas_price.simple_cu_price,
            profitable_gas_price=token.profitable_gas_price,
        )


class ExecTxRequest(BaseModel):
    tx: MpTxModel
    token: ExecTokenModel

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.tx.tx_id)

    @cached_property
    def sender(self) -> NeonAddress:
        return NeonAddress.from_raw(self.tx.sender, self.token.chain_id)


class ExecTxResp(BaseModel):
    result: bool


class CompleteStuckTxRequest(BaseModel):
    stuck_tx: MpStuckTxModel

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.stuck_tx.tx_id, is_stuck=True)


class CompleteStuckTxResp(BaseModel):
    result: bool


class DestroyTreeAccountRequest(BaseModel):
    tree_address: SolPubKeyField
    neon_tx_hash: EthTxHashField
    payer: NeonAddressField
    nonce: int
    token: ExecTokenModel

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.neon_tx_hash.ident, skd_tree=self.tree_address.ident, is_destroy=True)


class DestroyTreeAccountResp(BaseModel):
    result: bool


class NeonAltModel(BaseModel):
    neon_tx_hash: EthTxHashField
    sol_alt_id: SolAltID


class DestroyAltListRequest(BaseModel):
    req_id: dict
    alt_list: list[NeonAltModel]


class DestroyAltListResp(BaseModel):
    result: bool


class ExecTxDoneCode(IntEnum):
    Done = 1
    Failed = 2
    NonceTooLow = 3
    NonceTooHigh = 4


ExecTxDoneCodeField = Annotated[
    ExecTxDoneCode,
    PlainValidator(lambda v: ExecTxDoneCode(v)),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class ExecTxDoneRequest(BaseModel):
    neon_tx_hash: EthTxHashField
    code: ExecTxDoneCodeField
    state_tx_cnt: int = 0
    balance: int = 0

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.neon_tx_hash.ident)


class ExecTxDoneResp(BaseModel):
    result: bool


class ExecTxDoneStuckRequest(BaseModel):
    neon_tx_hash: EthTxHashField
    code: ExecTxDoneCodeField

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.neon_tx_hash.ident)


class ExecTxDoneStuckResp(BaseModel):
    result: bool


class ExecTxNotifyStatusRequest(BaseModel):
    base_tx_hash: EthTxHashField
    neon_tx_hash: EthTxHashField
    exec_pct: int

    @cached_property
    def req_id(self) -> dict:
        return dict(tx=self.neon_tx_hash.ident)


class ExecTxNotifyStatusResp(BaseModel):
    result: bool

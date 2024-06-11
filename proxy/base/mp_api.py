from __future__ import annotations

import time
from enum import IntEnum
from typing import Annotated

from pydantic import Field, PlainValidator, PlainSerializer
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.hash import EthTxHashField, EthTxHash, EthAddress
from common.neon.account import NeonAccountField
from common.neon.transaction_model import NeonTxModel
from common.solana.pubkey import SolPubKeyField
from common.utils.cached import cached_property, cached_method
from common.utils.pydantic import BaseModel

MP_ENDPOINT = "/api/v1/mempool/"


class MpTxModel(BaseModel):
    eth_tx_data: EthBinStrField
    chain_id: int

    order_gas_price: int
    start_time_nsec: int

    @classmethod
    def from_raw(cls, eth_tx_rlp: bytes, chain_id: int) -> Self:
        return cls(
            eth_tx_data=eth_tx_rlp,
            chain_id=chain_id,
            order_gas_price=0,
            start_time_nsec=time.monotonic_ns(),
        )

    @cached_property
    def neon_tx(self) -> NeonTxModel:
        eth_tx_rlp = self.eth_tx_data.to_bytes()
        return NeonTxModel.from_raw(eth_tx_rlp)

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self.neon_tx.neon_tx_hash

    @cached_property
    def tx_id(self) -> str:
        return self.neon_tx_hash.ident

    @property
    def sender(self) -> EthAddress:
        return self.neon_tx.from_address

    @property
    def nonce(self) -> int:
        return self.neon_tx.nonce

    @property
    def gas_price(self) -> int:
        # this property is used for sorting, and can be changed by the mempool logic
        # TODO EIP1559: should we rely upon max_priority_fee_per_gas?
        return self.order_gas_price or self.neon_tx.gas_price

    @property
    def process_time_nsec(self) -> int:
        return time.monotonic_ns() - self.start_time_nsec

    @property
    def process_time_msec(self) -> float:
        return self.process_time_nsec / (10**6)

    @cached_method
    def to_string(self) -> str:
        return f"{self.neon_tx_hash}:0x{self.nonce:x}:0x{self.chain_id:x}:{self.gas_price}"

    def set_gas_price(self, value: int) -> None:
        object.__setattr__(self, "order_gas_price", value)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class MpStuckTxModel(BaseModel):
    neon_tx_hash: EthTxHashField
    holder_address: SolPubKeyField
    alt_address_list: list[SolPubKeyField]

    start_time_nsec: int

    @classmethod
    def from_db(cls, data: dict) -> Self:
        return cls(
            neon_tx_hash=data["neon_tx_hash"],
            holder_address=data["holder_address"],
            alt_address_list=data.get("alt_address_list", list()),
            start_time_nsec=time.monotonic_ns(),
        )

    @classmethod
    def from_raw(cls, neon_tx_hash: EthTxHash, holder_address: SolPubKeyField) -> Self:
        return cls(
            neon_tx_hash=neon_tx_hash,
            holder_address=holder_address,
            alt_address_list=list(),
            start_time_nsec=time.monotonic_ns(),
        )

    @cached_method
    def to_string(self) -> str:
        return f"{self.neon_tx_hash}:{self.holder_address}"

    @cached_property
    def tx_id(self) -> str:
        return self.neon_tx_hash.ident

    @property
    def process_time_nsec(self) -> int:
        return time.monotonic_ns() - self.start_time_nsec

    @property
    def process_time_msec(self) -> float:
        return self.process_time_nsec / (10**6)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class MpTokenGasPriceModel(BaseModel):
    chain_id: int
    token_name: str
    token_mint: SolPubKeyField
    token_price_usd: int
    is_default_token: bool

    suggested_gas_price: int
    is_const_gas_price: bool
    min_acceptable_gas_price: int
    min_executable_gas_price: int


class MpGasPriceModel(BaseModel):
    chain_token_price_usd: int

    operator_fee: int
    cu_price: int
    simple_cu_price: int

    min_wo_chain_id_acceptable_gas_price: int

    default_token: MpTokenGasPriceModel
    token_dict: dict[str, MpTokenGasPriceModel] = Field(default_factory=dict)

    @cached_property
    def chain_dict(self) -> dict[int, MpTokenGasPriceModel]:
        return {token.chain_id: token for token in self.token_dict.values()}

    @property
    def is_empty(self) -> bool:
        return not self.token_dict


class MpRequest(BaseModel):
    ctx_id: str
    chain_id: int


class MpTxCntRequest(BaseModel):
    ctx_id: str
    sender: NeonAccountField


class MpTxCntResp(BaseModel):
    tx_cnt: int | None


class MpTxRequest(BaseModel):
    ctx_id: str
    tx: MpTxModel
    state_tx_cnt: int


class MpTxRespCode(IntEnum):
    Success = 0
    NonceTooLow = 1
    NonceTooHigh = 2
    Underprice = 3
    AlreadyKnown = 4
    UnknownChainID = 5
    Unspecified = 255


MpTxRespCodeField = Annotated[
    MpTxRespCode,
    PlainValidator(lambda v: MpTxRespCode(v)),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class MpTxResp(BaseModel):
    code: MpTxRespCodeField
    state_tx_cnt: int | None


class MpGetTxByHashRequest(BaseModel):
    ctx_id: str
    neon_tx_hash: EthTxHashField


class MpGetTxBySenderNonceRequest(BaseModel):
    ctx_id: str
    sender: NeonAccountField
    tx_nonce: int


class MpGetTxResp(BaseModel):
    tx: NeonTxModel | None


class MpTxPoolContentResp(BaseModel):
    pending_list: list[NeonTxModel]
    queued_list: list[NeonTxModel]

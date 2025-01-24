from __future__ import annotations

import time
from enum import IntEnum
from typing import Annotated, ClassVar

from pydantic import Field, PlainValidator, PlainSerializer
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.hash import EthTxHashField, EthTxHash, EthAddress
from common.neon.address import NeonAddressField
from common.neon.transaction_model import NeonTxModel, NeonSkdTxModel
from common.solana.pubkey import SolPubKeyField, SolPubKey
from common.solana.signature import SolTxSigField, SolTxSig
from common.utils.cached import cached_property, cached_method
from common.utils.pydantic import BaseModel

MP_ENDPOINT = "/api/v1/mempool/"


class MpTxModel(BaseModel):
    rlp_tx: EthBinStrField
    chain_id: int
    sol_skd_tx_sig: SolTxSigField
    sol_skd_payer: SolPubKeyField
    #
    order_gas_price: int = 0
    start_time_nsec: int

    @classmethod
    def from_param(cls, rlp_tx: bytes, chain_id: int, sol_skd_tx_sig: SolTxSig, sol_skd_payer: SolPubKey) -> Self:
        return cls(
            rlp_tx=rlp_tx,
            chain_id=chain_id,
            sol_skd_tx_sig=sol_skd_tx_sig,
            sol_skd_payer=sol_skd_payer,
            #
            start_time_nsec=time.monotonic_ns(),
        )

    @classmethod
    def from_skd_tx(cls, skd_tx: NeonSkdTxModel) -> Self:
        return cls.from_param(
            rlp_tx=skd_tx.rlp_tx.to_bytes(),
            chain_id=skd_tx.chain_id,
            sol_skd_tx_sig=skd_tx.sol_skd_tx_sig,
            sol_skd_payer=skd_tx.sol_skd_payer,
        )

    @cached_property
    def neon_tx(self) -> NeonTxModel:
        param_dict = dict(
            rlp_tx=self.rlp_tx.to_bytes(),
            sol_skd_tx_sig=self.sol_skd_tx_sig,
            sol_skd_payer=self.sol_skd_payer,
        )

        return NeonTxModel.from_raw(param_dict)

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
    def payer(self) -> EthAddress:
        return self.neon_tx.payer

    @property
    def receiver(self) -> EthAddress:
        if self.neon_tx.to_address.is_empty:
            return self.neon_tx.contract
        return self.neon_tx.to_address

    @property
    def nonce(self) -> int:
        return self.neon_tx.nonce

    @property
    def gas_price(self) -> int:
        # this property is used for sorting, and can be changed by the mempool logic
        #   Operator is guaranteed to receive payment from the base fee per price
        return self.order_gas_price or self.neon_tx.operator_fee_per_gas

    @property
    def gas_limit(self) -> int:
        return self.neon_tx.gas_limit

    @property
    def process_time_nsec(self) -> int:
        return time.monotonic_ns() - self.start_time_nsec

    @property
    def process_time_msec(self) -> float:
        return self.process_time_nsec / pow(10, 6)

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
        return self.process_time_nsec / pow(10, 6)

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
    is_layer0_token: bool

    suggested_gas_price: int
    profitable_gas_price: int
    pct_gas_price: int
    is_const_gas_price: bool
    min_acceptable_gas_price: int
    min_executable_gas_price: int


class MpGasPriceModel(BaseModel):
    chain_token_price_usd: int

    operator_fee: int
    priority_fee: int
    cu_price: int
    cu_price_pct: int
    simple_cu_price: int

    min_wo_chain_id_acceptable_gas_price: int

    default_token: MpTokenGasPriceModel
    layer0_token: MpTokenGasPriceModel
    token_dict: dict[str, MpTokenGasPriceModel] = Field(default_factory=dict)

    @cached_property
    def chain_dict(self) -> dict[int, MpTokenGasPriceModel]:
        return {token.chain_id: token for token in self.token_dict.values()}

    @property
    def is_empty(self) -> bool:
        return not self.token_dict


class MpRequest(BaseModel):
    ctx_id: dict
    chain_id: int


class MpTxCntRequest(BaseModel):
    ctx_id: dict
    sender: NeonAddressField


class MpTxCntResp(BaseModel):
    tx_cnt: int | None


class MpTxRequest(BaseModel):
    ctx_id: dict
    tx: MpTxModel
    state_tx_cnt: int
    balance: int


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
    ctx_id: dict
    neon_tx_hash: EthTxHashField


class MpGetTxBySenderNonceRequest(BaseModel):
    ctx_id: dict
    sender: NeonAddressField
    tx_nonce: int


class MpGetTxResp(BaseModel):
    tx: NeonTxModel | None


class MpTxPoolContentResp(BaseModel):
    pending_list: list[NeonTxModel]
    queued_list: list[NeonTxModel]


class MpGetTxStatusListBySender(BaseModel):
    ctx_id: dict
    sender: NeonAddressField
    state_tx_cnt: int
    balance: int


class MpTxExecPctModel(BaseModel):
    neon_tx_hash: EthTxHashField
    exec_pct: int


class MpTxStatusModel(BaseModel):
    neon_tx_hash: EthTxHashField
    gas_price: int = 0
    nonce: int = 0
    cost: int = 0
    age_nsec: int = 0
    exec_pct_list: list[MpTxExecPctModel]

    @classmethod
    def from_raw(cls, tx: MpTxModel, exec_pct_list: list[MpTxExecPctModel]) -> Self:
        return cls(
            neon_tx_hash=tx.neon_tx_hash,
            gas_price=tx.neon_tx.base_fee_per_gas,
            nonce=tx.nonce,
            cost=tx.neon_tx.cost,
            age_nsec=tx.process_time_nsec,
            exec_pct_list=exec_pct_list,
        )

    def get_exec_pct(self, neon_tx_hash: EthTxHash) -> int:
        return next((p.exec_pct for p in self.exec_pct_list if p.neon_tx_hash == neon_tx_hash), 0)

    @cached_property
    def age_sec(self) -> int:
        return self.age_nsec // pow(10, 9)


class MpTxStatusListResp(BaseModel):
    state_tx_cnt: int
    balance: int
    min_exec_gas_price: int
    in_processing: bool
    tx_status_list: list[MpTxStatusModel]

    _default: ClassVar[MpTxStatusListResp | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(
                state_tx_cnt=0,
                balance=0,
                min_exec_gas_price=0,
                in_processing=False,
                tx_status_list=list(),
            )
        return cls._default

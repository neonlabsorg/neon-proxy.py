from __future__ import annotations

from typing_extensions import Self, ClassVar

from common.ethereum.hash import EthAddressField, EthAddress
from common.solana.pubkey import SolPubKey, SolPubKeyField
from common.solana.transaction_model import SolTxModel
from common.utils.cached import cached_method
from common.utils.pydantic import BaseModel

OP_RESOURCE_ENDPOINT = "/api/v1/resource/"


class OpGetResourceRequest(BaseModel):
    req_id: dict
    chain_id: int | None


class OpFreeResourceRequest(BaseModel):
    req_id: dict
    is_good: bool
    resource: OpResourceModel


class OpResourceResp(BaseModel):
    result: bool


class OpResourceModel(BaseModel):
    owner: SolPubKeyField
    holder_address: SolPubKeyField
    resource_id: int
    eth_address: EthAddressField
    token_sol_address: SolPubKeyField

    _default: ClassVar[OpResourceModel | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = OpResourceModel(
                owner=SolPubKey.default(),
                holder_address=SolPubKey.default(),
                resource_id=0,
                eth_address=EthAddress.default(),
                token_sol_address=SolPubKey.default(),
            )
        return cls._default

    @cached_method
    def to_string(self) -> str:
        return f"{self.owner}:{self.resource_id}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @property
    def is_empty(self) -> bool:
        return self.owner.is_empty


class OpGetTokenSolAddressRequest(BaseModel):
    req_id: dict
    owner: SolPubKeyField
    chain_id: int


class OpTokenSolAddressModel(BaseModel):
    owner: SolPubKeyField
    eth_address: EthAddressField
    token_sol_address: SolPubKeyField


class OpSignSolTxListRequest(BaseModel):
    req_id: dict
    owner: SolPubKeyField
    tx_list: list[SolTxModel]


class OpSolTxListResp(BaseModel):
    tx_list: list[SolTxModel]


class OpGetSignerKeyListRequest(BaseModel):
    req_id: dict


class OpSignerKeyListResp(BaseModel):
    signer_key_list: list[SolPubKeyField]


class OpGetEthAddressListRequest(BaseModel):
    req_id: dict


class OpEthAddressModel(BaseModel):
    owner: SolPubKeyField
    eth_address: EthAddressField


class OpEthAddressListResp(BaseModel):
    eth_address_list: list[OpEthAddressModel]


class OpWithdrawTokenRequest(BaseModel):
    req_id: dict


class OpWithdrawTokenResp(BaseModel):
    total_amount_dict: dict[str, int]

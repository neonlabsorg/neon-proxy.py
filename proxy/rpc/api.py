from __future__ import annotations

from typing import ClassVar

from pydantic import Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.commit_level import EthCommitField, EthCommit
from common.ethereum.hash import (
    EthBlockHashField,
    EthBlockHash,
    EthAddressField,
    EthHash32Field,
    EthTxHashField,
)
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.evm_log_decoder import NeonTxEventModel
from common.solana.account import SolAccountModel
from common.solana.pubkey import SolPubKeyField
from common.solana.signature import SolTxSigField
from common.utils.pydantic import HexUIntField, RootModel


class RpcBlockParamModel(BaseJsonRpcModel):
    blockHash: EthBlockHashField | None = None
    blockNumber: HexUIntField | EthCommitField | None = None

    @property
    def is_block_hash(self) -> bool:
        return self.blockHash is not None

    @property
    def is_block_name(self) -> bool:
        return isinstance(self.blockNumber, str)

    @property
    def is_block_number(self) -> bool:
        return isinstance(self.blockNumber, int)

    def model_post_init(self, _context) -> None:
        if self.is_block_hash == (self.is_block_number or self.is_block_name):
            if not self.is_block_hash:
                raise ValueError("One of properties should be defined: blockHash or blockNumber")
            else:
                raise ValueError("Both properties can't be defined: blockHash or blockNumber")


class RpcBlockRequest(RootModel):
    root: HexUIntField | EthCommitField | RpcBlockParamModel

    _latest: ClassVar[RpcBlockRequest | None] = None

    @classmethod
    def latest(cls) -> Self:
        if not cls._latest:
            cls._latest = cls(root=EthCommit.Latest)
        return cls._latest

    @property
    def is_block_hash(self) -> bool:
        return isinstance(self.root, RpcBlockParamModel) and self.root.is_block_hash

    @property
    def is_block_number(self) -> bool:
        return (isinstance(self.root, RpcBlockParamModel) and self.root.is_block_number) or isinstance(self.root, int)

    @property
    def is_block_name(self) -> bool:
        return (isinstance(self.root, RpcBlockParamModel) and self.root.is_block_name) or isinstance(self.root, str)

    @property
    def block_hash(self) -> EthBlockHash:
        assert self.is_block_hash
        return self.root.blockHash

    @property
    def block_number(self) -> int:
        assert self.is_block_number
        if isinstance(self.root, RpcBlockParamModel):
            return self.root.blockNumber
        return self.root

    @property
    def block_name(self) -> EthCommit:
        assert self.is_block_name
        if isinstance(self.root, RpcBlockParamModel):
            return self.root.blockNumber
        return self.root

    def model_post_init(self, _ctx) -> None:
        if self.root is None:
            raise ValueError(f"{type(self).__name__} can't be null")


class RpcNeonCallRequest(BaseJsonRpcModel):
    sol_account_dict: dict[SolPubKeyField, SolAccountModel] = Field(
        default_factory=dict,
        validation_alias="solanaOverrides",
    )

    _default: ClassVar[RpcNeonCallRequest | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(solanaOverrides=dict())
        return cls._default


class RpcEthTxEventModel(BaseJsonRpcModel):
    address: EthAddressField
    data: EthBinStrField
    topics: list[EthHash32Field]
    blockHash: EthBlockHashField
    blockNumber: HexUIntField
    transactionHash: EthTxHashField
    transactionIndex: HexUIntField
    logIndex: HexUIntField | None

    removed: bool = False

    @classmethod
    def from_raw(cls, event: NeonTxEventModel) -> Self:
        return cls(**cls._to_dict(event))

    @staticmethod
    def _to_dict(event: NeonTxEventModel) -> dict:
        return dict(
            address=event.address,
            data=event.data,
            topics=event.topic_list,
            blockHash=event.block_hash,
            blockNumber=event.slot,
            transactionHash=event.neon_tx_hash,
            transactionIndex=event.neon_tx_idx,
            logIndex=event.block_log_idx,
        )


class RpcNeonTxEventModel(RpcEthTxEventModel):
    solanaTransactionSignature: SolTxSigField
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    neonEventType: str
    neonEventLevel: int
    neonEventOrder: int
    neonIsHidden: bool
    neonIsReverted: bool

    @classmethod
    def from_raw(cls, event: NeonTxEventModel) -> Self:
        return cls(
            **cls._to_dict(event),
            solanaTransactionSignature=event.sol_tx_sig,
            solanaInstructionIndex=event.sol_ix_idx,
            solanaInnerInstructionIndex=event.sol_inner_ix_idx,
            neonEventType=event.event_type.name,
            neonEventLevel=event.event_level,
            neonEventOrder=event.event_order,
            neonIsHidden=event.is_hidden,
            neonIsReverted=event.is_reverted,
        )

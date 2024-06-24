from __future__ import annotations

from typing import ClassVar

from pydantic import AliasChoices, Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField, EthBinStr
from common.ethereum.hash import EthAddressField, EthHash32Field, EthAddress, EthTxHash, EthBlockHashField, \
    EthTxHashField
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EmulNeonCallModel
from common.utils.pydantic import HexUIntField


class RpcAccessItemModel(BaseJsonRpcModel):
    address: EthAddressField
    storageKeys: list[EthHash32Field]


class RpcEthTxRequest(BaseJsonRpcModel):
    txType: HexUIntField = Field(default=0, validation_alias="type")
    fromAddress: EthAddressField = Field(
        default=EthAddress.default(),
        validation_alias=AliasChoices("from", "fromAddress"),
    )
    toAddress: EthAddressField = Field(
        default=EthAddress.default(),
        validation_alias=AliasChoices("to", "toAddress"),
    )
    data: EthBinStrField = Field(
        default=EthBinStr.default(),
        validation_alias=AliasChoices("data", "input"),
    )
    value: HexUIntField = Field(default=0)
    nonce: HexUIntField = Field(default=0)

    gas: HexUIntField = Field(default=2**64)
    gasPrice: HexUIntField = Field(default=2**64)
    maxFeePerGas: HexUIntField = Field(default=2**64)
    maxPriorityFeePerGas: HexUIntField = Field(default=2**64)

    accessList: list[RpcAccessItemModel] = Field(default_factory=list)
    chainId: HexUIntField = Field(default=0)

    _default: ClassVar[RpcEthTxRequest | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(
                fromAddress=EthAddress.default(),
                toAddress=EthAddress.default(),
                data=EthBinStr.default(),
            )
        return cls._default

    def to_emulation_call(self, chain_id: int) -> EmulNeonCallModel:
        return EmulNeonCallModel(
            from_address=self.fromAddress,
            to_address=self.toAddress,
            value=self.value,
            data=self.data.to_bytes(),
            gas_limit=self.gas,
            gas_price=self.gasPrice,
            chain_id=chain_id
        )

    def to_neon_tx(self) -> NeonTxModel:
        return NeonTxModel(
            tx_type=self.txType,
            neon_tx_hash=EthTxHash.default(),
            from_address=self.fromAddress,
            to_address=self.toAddress,
            contract=EthAddress.default(),
            nonce=self.nonce,
            gas_price=self.gasPrice,
            gas_limit=self.gas,
            value=self.value,
            call_data=self.data,
            v=0,
            r=0,
            s=0,
        )


class RpcEthTxResp(BaseJsonRpcModel):
    blockHash: EthBlockHashField | None
    blockNumber: HexUIntField | None
    transactionIndex: HexUIntField | None
    txHash: EthTxHashField = Field(serialization_alias="hash")
    txType: HexUIntField = Field(serialization_alias="type")
    fromAddress: EthAddressField = Field(serialization_alias="from")
    nonce: HexUIntField
    gasPrice: HexUIntField
    gas: HexUIntField
    toAddress: EthAddressField = Field(serialization_alias="to")
    value: HexUIntField
    data: EthBinStrField = Field(serialization_alias="input")
    chainId: HexUIntField | None
    v: HexUIntField
    r: HexUIntField
    s: HexUIntField

    @classmethod
    def from_raw(cls, meta: NeonTxMetaModel | NeonTxModel) -> Self:
        if isinstance(meta, NeonTxMetaModel):
            tx = meta.neon_tx

            rcpt = meta.neon_tx_rcpt
            blockhash = rcpt.block_hash
            slot = rcpt.slot
            tx_idx = rcpt.neon_tx_idx
        else:
            tx = meta

            blockhash = None
            slot = None
            tx_idx = None

        return cls(
            blockHash=blockhash,
            blockNumber=slot,
            transactionIndex=tx_idx,
            txHash=tx.neon_tx_hash,
            txType=tx.tx_type,
            fromAddress=tx.from_address.to_string(),
            nonce=tx.nonce,
            gasPrice=tx.gas_price,
            gas=tx.gas_limit,
            toAddress=tx.to_address,
            value=tx.value,
            data=tx.call_data,
            chainId=tx.chain_id,
            v=tx.v,
            r=tx.r,
            s=tx.s,
        )
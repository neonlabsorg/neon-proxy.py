from __future__ import annotations

from typing import Any, ClassVar

from pydantic import AliasChoices, Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField, EthBinStr
from common.ethereum.hash import (
    EthAddressField,
    EthHash32Field,
    EthAddress,
    EthTxHash,
    EthBlockHashField,
    EthTxHashField,
)
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel, NeonTxType
from common.neon_rpc.api import CoreApiTxModel
from common.solana.pubkey import SolPubKeyField
from common.solana.signature import SolTxSigField
from common.utils.cached import cached_property
from common.utils.pydantic import HexUIntField


class RpcAccessItemModel(BaseJsonRpcModel):
    address: EthAddressField
    storageKeys: list[EthHash32Field]


class BaseEthGasModel(BaseJsonRpcModel):
    gasPrice: HexUIntField = Field(default=2 ** 64)
    maxFeePerGas: HexUIntField = Field(default=2 ** 64)
    maxPriorityFeePerGas: HexUIntField = Field(default=0)

    nonce: HexUIntField | None = Field(default=None)
    chainId: HexUIntField = Field(default=0)


class BaseEthCallModel(BaseJsonRpcModel):
    fromAddress: EthAddressField = Field(
        default=EthAddress.default(),
        validation_alias=AliasChoices("from", "fromAddress"),
    )
    toAddress: EthAddressField = Field(
        default=EthAddress.default(),
        validation_alias=AliasChoices("to", "toAddress"),
    )
    data_v1: EthBinStrField = Field(default=EthBinStr.default(), validation_alias="data")
    data_v2: EthBinStrField = Field(default=EthBinStr.default(), validation_alias="input")

    gas: HexUIntField = Field(default=2 ** 64)
    value: HexUIntField = Field(default=0)

    @cached_property
    def data(self) -> EthBinStr:
        return self.data_v2 if not self.data_v2.is_empty else self.data_v1


class RpcEthTxRequest(BaseEthGasModel, BaseEthCallModel):
    txType: HexUIntField = Field(default=NeonTxType.Legacy.value, validation_alias="type")
    accessList: list[RpcAccessItemModel] = Field(default_factory=list)

    _default: ClassVar[RpcEthTxRequest | None] = None

    def model_post_init(self, _ctx: Any) -> None:
        if self.maxPriorityFeePerGas > self.maxFeePerGas:
            raise ValueError("maxPriorityFeePerGas should be not greater than maxFeePerGas")

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls()
        return cls._default

    def to_core_tx(self, chain_id: int) -> CoreApiTxModel:
        return CoreApiTxModel(
            from_address=self.fromAddress,
            payer=self.fromAddress,
            to_address=self.toAddress,
            nonce=self.nonce,
            value=self.value,
            data=self.data.to_bytes(),
            gas_limit=self.gas,
            gas_price=(
                self.maxFeePerGas - self.maxPriorityFeePerGas
                if NeonTxType.is_dynamic_gas_tx(self.txType)
                else self.gasPrice
            ),
            chain_id=chain_id,
        )

    def to_neon_tx(self) -> NeonTxModel:
        return NeonTxModel(
            tx_type=self.txType,
            neon_tx_hash=EthTxHash.default(),
            from_address=self.fromAddress,
            payer=self.payerAddress,
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
    blockHash: EthBlockHashField | None = None
    blockNumber: HexUIntField | None = None
    transactionIndex: HexUIntField | None = None
    txHash: EthTxHashField = Field(serialization_alias="hash")
    txType: HexUIntField = Field(serialization_alias="type")
    fromAddress: EthAddressField = Field(serialization_alias="from")
    scheduledPayer: EthAddressField = EthAddress.default()
    scheduledSolanaPayer: SolPubKeyField | None = Field(None)
    nonce: HexUIntField
    scheduledIndex: HexUIntField | None = None
    gasPrice: HexUIntField
    maxPriorityFeePerGas: HexUIntField | None = None
    maxFeePerGas: HexUIntField | None = None
    gas: HexUIntField
    toAddress: EthAddressField = Field(serialization_alias="to")
    value: HexUIntField
    data: EthBinStrField = Field(serialization_alias="input")
    # scheduledIntent: EthAddressField | None = None
    # scheduledIntentInput: EthBinStrField | None = None
    chainId: HexUIntField | None
    v: HexUIntField | None = None
    r: HexUIntField | None = None
    s: HexUIntField | None = None
    scheduledSolanaSignature: SolTxSigField | None = None

    @classmethod
    def from_raw(cls, meta: NeonTxMetaModel | NeonTxModel) -> Self:
        tx = meta.neon_tx if isinstance(meta, NeonTxMetaModel) else meta

        return cls(
            txHash=tx.neon_tx_hash,
            txType=tx.tx_type,
            fromAddress=tx.from_address,
            nonce=tx.nonce,
            gasPrice=tx.effective_gas_price,
            gas=tx.gas_limit,
            toAddress=tx.to_address,
            value=tx.value,
            data=tx.call_data,
            # chainId will be returned even for the legacy transactions.
            # N.B. Various RPC providers differ in this regard.
            # For example Infura claims to NOT return it for the legacy transaction in the docs, but they still do...
            chainId=tx.chain_id,
            **cls._to_dict(meta),
        )

    @staticmethod
    def _to_dict(meta: NeonTxMetaModel) -> dict:
        tx = meta.neon_tx if isinstance(meta, NeonTxMetaModel) else meta
        param_dict = dict()

        if isinstance(meta, NeonTxMetaModel):
            rcpt = meta.neon_tx_rcpt
            param_dict = dict(
                blockHash=rcpt.block_hash,
                blockNumber=rcpt.slot,
                transactionIndex=rcpt.neon_tx_idx,
            )

        if not tx.is_legacy_tx:
            param_dict.update(
                dict(
                    maxPriorityFeePerGas=tx.max_priority_fee_per_gas,
                    maxFeePerGas=tx.max_fee_per_gas,
                )
            )

        if tx.is_scheduled_tx:
            param_dict.update(
                dict(
                    scheduledIndex=tx.index,
                    scheduledPayer=tx.payer,
                    scheduledSolanaPayer=tx.sol_skd_payer,
                    scheduledSolanaSignature=tx.sol_skd_tx_sig,
                    # scheduledIntent=tx.intent,
                    # scheduledIntentInput=tx.intent_call_data,
                )
            )
        else:
            param_dict.update(
                dict(
                    v=tx.v,
                    r=tx.r,
                    s=tx.s,
                )
            )

        return param_dict

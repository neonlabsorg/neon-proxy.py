from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import ClassVar, Final, Annotated, Literal, Any, Sequence

from pydantic import Field, PlainValidator, PlainSerializer
from strenum import StrEnum
from typing_extensions import Self

from common.ethereum import revert_message
from common.ethereum.bin_str import EthBinStrField
from common.ethereum.commit_level import EthCommit
from common.ethereum.hash import (
    EthTxHashField,
    EthAddressField,
    EthBlockHashField,
    EthHash32Field,
    EthZeroAddressField,
    EthAddress,
    EthNotNoneAddressField,
    EthTxHash,
)
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.address import NeonAddress
from common.neon.block import NeonBlockHdrModel
from common.neon.cancel_error import CancelErrorData
from common.neon.evm_log_decoder import NeonTxEventModel
from common.neon.neon_program import NeonEvmIxCode
from common.neon.transaction_decoder import SolNeonAltTxIxModel, SolNeonTxIxMetaModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon_rpc.api import NeonSkdTreeModel, NeonSkdTreeNodeModel
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKeyField, SolPubKey, SolNotNonePubKeyField
from common.solana.signature import SolTxSigField, SolTxSig, SolTxSigSlotInfo
from common.utils.pydantic import HexUIntField, Hex256UIntField, Hex8UIntField, Base58Field, HexUInt64Field
from .api import RpcBlockRequest, RpcEthTxEventModel, RpcNeonTxEventModel
from .server_abc import NeonProxyApi
from ..base.mp_api import MpTxStatusModel
from ..base.rpc_api import RpcEthTxResp

_LOG = logging.getLogger(__name__)


class _RpcNeonTxReceiptDetail(StrEnum):
    Eth = "ethereum"
    Neon = "neon"
    SolTxList = "solanaTransactionList"
    Compact = "compact"

    @classmethod
    def from_raw(cls, tag: str | _RpcNeonTxReceiptDetail) -> Self:
        if isinstance(tag, _RpcNeonTxReceiptDetail):
            return tag

        try:
            return cls(tag)
        except (BaseException,):
            raise ValueError(f"Should be one of: {cls.Neon}, {cls.Eth}, {cls.SolTxList}, {cls.Compact}")


_RpcNeonTxReceiptDetailField = Annotated[_RpcNeonTxReceiptDetail, PlainValidator(_RpcNeonTxReceiptDetail.from_raw)]


class _RpcEthTxReceiptResp(BaseJsonRpcModel):
    transactionHash: EthTxHashField
    transactionIndex: HexUIntField
    txType: HexUIntField = Field(serialization_alias="type")
    blockHash: EthBlockHashField
    blockNumber: HexUIntField
    fromAddress: EthAddressField = Field(serialization_alias="from")
    toAddress: EthAddressField = Field(serialization_alias="to")
    effectiveGasPrice: HexUIntField
    gasUsed: HexUIntField
    cumulativeGasUsed: HexUIntField
    contractAddress: EthAddressField
    root: EthHash32Field
    status: HexUIntField
    logsBloom: Hex256UIntField
    logs: list[RpcNeonTxEventModel | RpcEthTxEventModel]
    scheduledParentTransactionHashes: list[EthTxHashField]
    scheduledChildTransactionHashes: list[EthTxHashField]
    #
    EmptyRoot: Final[EthHash32Field] = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

    @classmethod
    def from_raw(cls, neon_tx_meta: NeonTxMetaModel) -> Self:
        rcpt = neon_tx_meta.neon_tx_rcpt
        return cls(
            **cls._to_dict(neon_tx_meta),
            logs=[RpcEthTxEventModel.from_raw(e) for e in rcpt.event_list if not e.is_hidden],
        )

    @classmethod
    def _to_dict(cls, neon_tx_meta: NeonTxMetaModel) -> dict:
        tx = neon_tx_meta.neon_tx
        rcpt = neon_tx_meta.neon_tx_rcpt

        return dict(
            transactionHash=tx.neon_tx_hash,
            transactionIndex=rcpt.neon_tx_idx,
            txType=tx.tx_type,
            blockHash=rcpt.block_hash,
            blockNumber=rcpt.slot,
            fromAddress=tx.from_address,
            toAddress=tx.to_address,
            effectiveGasPrice=neon_tx_meta.effective_gas_price,
            gasUsed=rcpt.total_gas_used,
            cumulativeGasUsed=rcpt.sum_gas_used,
            contractAddress=tx.contract,
            root=cls.EmptyRoot,
            status=rcpt.status,
            logsBloom=rcpt.log_bloom,
            scheduledParentTransactionHashes=rcpt.parent_tx_list,
            scheduledChildTransactionHashes=rcpt.child_tx_list,
        )


class _RpcNeonCostModel(BaseJsonRpcModel):
    neonOperatorAddress: SolPubKeyField
    solanaLamportExpense: int
    neonAlanIncome: int


@dataclass
class _RpcNeonCostDraft:
    neonOperatorAddress: SolPubKeyField
    solanaLamportExpense: int = 0
    neonAlanIncome: int = 0

    def to_clean_copy(self) -> _RpcNeonCostModel:
        return _RpcNeonCostModel.model_validate(self, from_attributes=True)


class _RpcNeonIxModel(BaseJsonRpcModel):
    solanaProgram: Literal["NeonEVM"] = "NeonEVM"
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    svmHeapSizeLimit: int
    svmCyclesLimit: int
    svmCyclesUsed: int
    neonInstructionCode: int
    neonInstructionName: str
    neonEvmSteps: int
    neonTotalEvmSteps: int
    neonGasUsed: int
    neonTotalGasUsed: int
    neonTransactionFee: int
    neonMiner: EthAddressField
    neonLogs: list[RpcNeonTxEventModel]

    @classmethod
    def from_raw(cls, neon_tx_meta: NeonTxMetaModel, ix_meta: SolNeonTxIxMetaModel) -> Self:
        tx = neon_tx_meta.neon_tx
        rcpt = neon_tx_meta.neon_tx_rcpt

        log_list = [
            RpcNeonTxEventModel.from_raw(event)
            for event in rcpt.event_list
            if (event.sol_tx_sig, event.sol_ix_idx, (event.sol_inner_ix_idx or 0))
            == (ix_meta.sol_tx_sig, ix_meta.sol_ix_idx, (ix_meta.sol_inner_ix_idx or 0))
        ]
        neon_tx_cost = tx.calc_cost(gas_limit=ix_meta.neon_gas_used, value=0)

        return cls(
            solanaInstructionIndex=ix_meta.sol_ix_idx,
            solanaInnerInstructionIndex=ix_meta.sol_inner_ix_idx,
            svmHeapSizeLimit=ix_meta.heap_size,
            svmCyclesLimit=ix_meta.cu_limit,
            svmCyclesUsed=ix_meta.used_cu_limit,
            neonInstructionCode=ix_meta.neon_ix_code,
            neonInstructionName=NeonEvmIxCode(ix_meta.neon_ix_code).name,
            neonEvmSteps=ix_meta.neon_step_cnt,
            neonTotalEvmSteps=ix_meta.neon_total_step_cnt,
            neonGasUsed=ix_meta.neon_gas_used,
            neonTotalGasUsed=ix_meta.neon_total_gas_used,
            neonTransactionFee=neon_tx_cost,
            neonMiner=ix_meta.neon_tx_ix_miner,
            neonLogs=log_list,
        )


class _RpcAltIxModel(BaseJsonRpcModel):
    solanaProgram: Literal["AddressLookupTable"] = "AddressLookupTable"
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    lookupTableInstructionCode: int
    lookupTableInstructionName: str
    lookupTableAddress: SolPubKeyField

    @classmethod
    def from_raw(cls, raw: SolNeonAltTxIxModel) -> Self:
        return cls(
            solanaInstructionIndex=raw.sol_ix_idx,
            solanaInnerInstructionIndex=raw.sol_inner_ix_idx,
            lookupTableInstructionCode=int(raw.alt_ix_code),
            lookupTableInstructionName=raw.alt_ix_code.name,
            lookupTableAddress=raw.alt_address,
        )


class _RpcSolReceiptModel(BaseJsonRpcModel):
    solanaTransactionSignature: SolTxSigField
    solanaTransactionIsSuccess: bool
    solanaBlockSlot: int
    solanaLamportExpense: int
    neonOperatorAddress: SolPubKeyField
    solanaInstructions: list[_RpcNeonIxModel | _RpcAltIxModel]


@dataclass
class _RpcSolReceiptDraft:
    solanaTransactionSignature: SolTxSig
    solanaTransactionIsSuccess: bool
    solanaBlockSlot: int
    solanaLamportExpense: int
    neonOperatorAddress: SolPubKey
    solanaInstructions: list[_RpcNeonIxModel | _RpcAltIxModel]

    @classmethod
    def from_raw(cls, raw: SolNeonAltTxIxModel | SolNeonTxIxMetaModel) -> Self:
        return cls(
            solanaTransactionSignature=raw.sol_tx_sig,
            solanaTransactionIsSuccess=raw.is_success,
            solanaBlockSlot=raw.slot,
            solanaLamportExpense=raw.sol_tx_cost.sol_expense,
            neonOperatorAddress=raw.sol_tx_cost.sol_signer,
            solanaInstructions=list(),
        )

    def to_clean_copy(self) -> _RpcSolReceiptModel:
        return _RpcSolReceiptModel.model_validate(self, from_attributes=True)


class _RpcNeonCancelResp(BaseJsonRpcModel):
    solanaTransactionSignature: SolTxSigField
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    source: str
    address: SolPubKeyField
    code: HexUIntField
    data: EthBinStrField
    message: str

    @classmethod
    def from_raw(cls, event: NeonTxEventModel) -> Self | None:
        raw_data = event.data.to_bytes()
        error_data = raw_data[1:]  # skip status(0x01 or 0x00)
        data = CancelErrorData.from_bytes(error_data)
        return cls(
            solanaTransactionSignature=event.sol_tx_sig,
            solanaInstructionIndex=event.sol_ix_idx,
            solanaInnerInstructionIndex=event.sol_inner_ix_idx,
            source=data.source.name,
            address=data.address,
            code=data.code,
            data=raw_data,
            message=data.message,
        )


class _RpcNeonRevertResp(BaseJsonRpcModel):
    solanaTransactionSignature: SolTxSigField
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    address: EthAddressField
    data: EthBinStrField
    message: str | None

    @classmethod
    def from_raw(cls, event: NeonTxEventModel) -> Self:
        return cls(
            solanaTransactionSignature=event.sol_tx_sig,
            solanaInstructionIndex=event.sol_ix_idx,
            solanaInnerInstructionIndex=event.sol_inner_ix_idx,
            address=event.address,
            data=event.data,
            message=revert_message.safe_decode(event.data.to_bytes()),
        )


class _RpcNeonTxReceiptResp(_RpcEthTxReceiptResp):
    solanaBlockHash: Base58Field
    solanaCompleteTransactionSignature: SolTxSigField
    solanaCompleteInstructionIndex: int
    solanaCompleteInnerInstructionIndex: int | None
    neonRawTransaction: EthBinStrField
    neonIsCanceled: bool
    neonCancelData: _RpcNeonCancelResp | None
    neonRevertData: _RpcNeonRevertResp | None
    solanaTransactions: list[_RpcSolReceiptModel]
    neonCosts: list[_RpcNeonCostModel]

    @classmethod
    def from_raw(
        cls,
        neon_tx_meta: NeonTxMetaModel,
        *,
        detail: _RpcNeonTxReceiptDetail = _RpcNeonTxReceiptDetail.Eth,
        sol_meta_list: Sequence[SolNeonTxIxMetaModel | SolNeonAltTxIxModel] = tuple(),
    ) -> _RpcEthTxReceiptResp | Self:
        if detail == _RpcNeonTxReceiptDetail.Eth:
            return _RpcEthTxReceiptResp.from_raw(neon_tx_meta)

        tx = neon_tx_meta.neon_tx
        rcpt = neon_tx_meta.neon_tx_rcpt
        if detail == _RpcNeonTxReceiptDetail.Compact:
            log_list, sol_tx_list, neon_cost_list = list(), list(), list()
        elif detail == _RpcNeonTxReceiptDetail.Neon:
            log_list = [RpcNeonTxEventModel.from_raw(e) for e in rcpt.event_list]
            sol_tx_list, neon_cost_list = list(), list()
        else:
            log_list = list()
            sol_tx_list, neon_cost_list = cls._to_sol_receipt_list(neon_tx_meta, sol_meta_list)

        cancel: _RpcNeonCancelResp | None = None
        revert: _RpcNeonRevertResp | None = None
        if neon_tx_meta.neon_tx_rcpt.is_failed:
            for idx, e in enumerate(reversed(rcpt.event_list)):
                if idx > 5:
                    break
                elif e.event_type == e.event_type.ExitRevert:
                    revert = _RpcNeonRevertResp.from_raw(e)
                    break
                elif e.is_reverted:
                    continue
                elif e.event_type == e.event_type.Cancel:
                    cancel = _RpcNeonCancelResp.from_raw(e)
                    break

        return cls(
            **cls._to_dict(neon_tx_meta),
            solanaBlockHash=rcpt.block_hash.to_bytes(),
            solanaCompleteTransactionSignature=rcpt.sol_tx_sig,
            solanaCompleteInstructionIndex=rcpt.sol_ix_idx,
            solanaCompleteInnerInstructionIndex=rcpt.sol_inner_ix_idx,
            neonRawTransaction=tx.to_rlp_tx(),
            neonIsCanceled=rcpt.is_canceled,
            logs=log_list,
            neonCancelData=cancel,
            neonRevertData=revert,
            solanaTransactions=sol_tx_list,
            neonCosts=neon_cost_list,
        )

    @staticmethod
    def _to_sol_receipt_list(
        neon_tx_meta: NeonTxMetaModel,
        sol_meta_list: Sequence[SolNeonTxIxMetaModel | SolNeonAltTxIxModel],
    ) -> tuple[list[_RpcSolReceiptModel], list[_RpcNeonCostModel]]:
        rcpt_list: list[_RpcSolReceiptModel] = list()
        cost_dict: dict[SolPubKey, _RpcNeonCostDraft] = dict()
        cost: _RpcNeonCostDraft | None = None
        rcpt: _RpcSolReceiptDraft | None = None

        def _update_list(_ix_meta: SolNeonTxIxMetaModel | SolNeonAltTxIxModel) -> None:
            nonlocal rcpt
            nonlocal cost

            if rcpt and (rcpt.solanaTransactionSignature != _ix_meta.sol_tx_sig):
                rcpt_list.append(rcpt.to_clean_copy())
                rcpt = None

            if not rcpt:
                rcpt = _RpcSolReceiptDraft.from_raw(_ix_meta)

                sol_signer = _ix_meta.sol_tx_cost.sol_signer
                if not (rcpt_cost := cost_dict.get(sol_signer, None)):
                    rcpt_cost = _RpcNeonCostDraft(sol_signer)
                    cost_dict[sol_signer] = rcpt_cost

                rcpt_cost.solanaLamportExpense += _ix_meta.sol_tx_cost.sol_expense
                cost = rcpt_cost

        for sol_meta in sol_meta_list:
            _update_list(sol_meta)
            if isinstance(sol_meta, SolNeonAltTxIxModel):
                rcpt.solanaInstructions.append(_RpcAltIxModel.from_raw(sol_meta))
            else:
                ix_meta = _RpcNeonIxModel.from_raw(neon_tx_meta, sol_meta)
                rcpt.solanaInstructions.append(ix_meta)
                cost.neonAlanIncome += ix_meta.neonTransactionFee

        if rcpt:
            rcpt_list.append(rcpt.to_clean_copy())

        cost_list = list(map(lambda x: x.to_clean_copy(), iter(cost_dict.values())))
        return rcpt_list, cost_list


class _RpcBlockResp(BaseJsonRpcModel):
    logsBloom: Hex256UIntField

    transactionsRoot: EthHash32Field
    receiptsRoot: EthHash32Field
    stateRoot: EthHash32Field

    uncles: list[EthHash32Field]
    sha3Uncles: EthHash32Field

    difficulty: HexUIntField
    totalDifficulty: HexUIntField
    extraData: EthBinStrField
    miner: EthZeroAddressField | None
    nonce: Hex8UIntField | None
    mixHash: EthHash32Field
    size: HexUIntField

    gasLimit: HexUIntField
    gasUsed: HexUIntField
    baseFeePerGas: HexUIntField
    blockHash: EthBlockHashField | None = Field(serialization_alias="hash")
    number: HexUIntField
    parentHash: EthBlockHashField
    timestamp: HexUIntField
    transactions: list[RpcEthTxResp | EthTxHashField]

    FakeHash: Final[EthHash32Field] = "0x" + "00" * 31 + "01"
    EmptyRoot: Final[EthHash32Field] = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    Sha3UncleHash: Final[EthHash32Field] = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

    @classmethod
    def from_raw(
        cls,
        block: NeonBlockHdrModel,
        tx_list: Sequence[NeonTxMetaModel],
        full: bool,
        base_fee_per_gas: int,
    ) -> Self:
        is_pending = block.commit == EthCommit.Pending

        total_gas_used = 0
        log_bloom = 0
        rpc_tx_list: list[RpcEthTxResp | EthTxHashField] = list()

        if not is_pending:
            block_hash = block.block_hash
            miner = EthAddress.default()
            nonce = 0
            for tx in tx_list:
                total_gas_used = max(tx.neon_tx_rcpt.sum_gas_used, total_gas_used)
                log_bloom |= tx.neon_tx_rcpt.log_bloom
                rpc_tx_list.append(RpcEthTxResp.from_raw(tx) if full else tx.neon_tx_hash)
        else:
            block_hash = None
            miner = None
            nonce = None

        return cls(
            logsBloom=log_bloom,
            transactionsRoot=cls.FakeHash if tx_list else cls.EmptyRoot,
            receiptsRoot=cls.FakeHash,
            stateRoot=cls.FakeHash,
            #
            uncles=list(),
            sha3Uncles=cls.Sha3UncleHash,
            difficulty=0,
            totalDifficulty=0,
            extraData=b"",
            mixHash=cls.FakeHash,
            size=1,
            #
            gasLimit=max(48_000_000_000_000, total_gas_used),
            gasUsed=total_gas_used,
            baseFeePerGas=base_fee_per_gas,
            number=block.slot,
            parentHash=block.parent_block_hash,
            timestamp=block.block_time,
            #
            miner=miner,
            nonce=nonce,
            blockHash=block_hash,
            transactions=rpc_tx_list,
        )


class _RpcNeonTxStatus(StrEnum):
    HighNonce = "HighNonce"
    InsufficientBalance = "InsufficientBalance"
    LowGasPrice = "LowGasPrice"
    NoTxBody = "NoTransactionBody"
    WaitForParentTx = "WaitForParentTransactions"
    NotStarted = "NotStarted"
    InProgress = "InProgress"
    Skipped = "Skipped"
    Done = "Done"

    @classmethod
    def from_raw(cls, value: str | _RpcNeonTxStatus) -> Self:
        if isinstance(value, cls):
            return value

        try:
            return cls(value)
        except (BaseException,):
            raise ValueError(f"Wrong _RpcMpNeonTxStatusField {value}")


_RpcNeonTxStatusField = Annotated[
    _RpcNeonTxStatus,
    PlainValidator(_RpcNeonTxStatus.from_raw),
    PlainSerializer(lambda x: x.value, return_type=str),
]


class _RpcNeonTxStatusModel(BaseJsonRpcModel):
    txHash: EthTxHashField = Field(serialization_alias="hash")
    status: _RpcNeonTxStatusField
    executionPercentage: HexUIntField
    age: HexUIntField


class _RpcNeonTreeNodeModel(BaseJsonRpcModel):
    transactionHash: EthTxHashField
    status: str
    resultHash: EthHash32Field
    gasLimit: HexUIntField
    value: HexUIntField
    childTransactionIndex: HexUIntField
    successExecutionLimit: HexUIntField
    parentCount: HexUIntField

    @classmethod
    def from_raw(cls, tree_node: NeonSkdTreeNodeModel) -> Self:
        return cls(
            transactionHash=tree_node.neon_tx_hash,
            status=tree_node.status.name,
            resultHash=tree_node.result_hash,
            gasLimit=tree_node.gas_limit,
            value=tree_node.value,
            childTransactionIndex=tree_node.child_tx_idx,
            successExecutionLimit=tree_node.success_exec_limit,
            parentCount=tree_node.parent_cnt,
        )


class _RpcNeonTreeAccountResp(BaseJsonRpcModel):
    address: SolPubKeyField
    status: str
    activeStatus: str
    payer: EthNotNoneAddressField
    chainId: HexUIntField
    nonce: HexUIntField
    lastSlot: HexUIntField
    maxFeePerGas: HexUIntField
    maxPriorityFeePerGas: HexUIntField
    balance: HexUIntField
    lastIndex: HexUIntField
    transactions: list[_RpcNeonTreeNodeModel]

    @classmethod
    def from_raw(cls, tree: NeonSkdTreeModel, nonce: int) -> Self:
        return cls(
            address=tree.address,
            status=tree.status.value,
            activeStatus=tree.active_status.name,
            payer=tree.payer,
            chainId=tree.chain_id,
            nonce=nonce,
            lastSlot=tree.last_slot,
            maxFeePerGas=tree.max_fee_per_gas,
            maxPriorityFeePerGas=tree.max_priority_fee_per_gas,
            balance=tree.balance,
            lastIndex=tree.last_idx,
            transactions=[_RpcNeonTreeNodeModel.from_raw(n) for n in tree.node_list],
        )


class NpBlockTxApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::BlockTransaction"

    @NeonProxyApi.method(name="eth_getTransactionByHash")
    async def get_tx_by_hash(self, ctx: HttpRequestCtx, tx_hash: EthTxHashField | SolTxSigField) -> RpcEthTxResp | None:
        if not (tx_hash := await self._get_neon_tx_hash(tx_hash)):
            return None

        if not (meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            if not (meta := await self._mp_client.get_tx_by_hash(self._get_ctx_id(ctx), tx_hash)):
                return None
        return RpcEthTxResp.from_raw(meta)

    @NeonProxyApi.method(name="neon_getTransactionBySenderNonce")
    async def get_tx_by_sender_nonce(
        self,
        ctx: HttpRequestCtx,
        sender: EthNotNoneAddressField | SolNotNonePubKeyField,
        nonce: HexUInt64Field,
        index: HexUInt64Field = 0,
    ) -> RpcEthTxResp | None:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(sender, SolPubKey))
        neon_addr = NeonAddress.from_raw(sender, chain_id)
        inc_no_chain_id = True if self._is_default_chain_id(ctx) else False
        if not (meta := await self._db.get_tx_by_sender_nonce(neon_addr, nonce, index, inc_no_chain_id)):
            if not (meta := await self._mp_client.get_tx_by_sender_nonce(self._get_ctx_id(ctx), neon_addr, nonce)):
                return None
        return RpcEthTxResp.from_raw(meta)

    @NeonProxyApi.method(name="eth_getTransactionReceipt")
    async def get_tx_receipt(self, tx_hash: EthTxHashField | SolTxSigField) -> _RpcEthTxReceiptResp | None:
        if not (tx_hash := await self._get_neon_tx_hash(tx_hash)):
            return None

        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            return None
        return _RpcEthTxReceiptResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getTransactionByBlockNumberAndIndex")
    async def get_tx_by_block_number_idx(
        self, block_tag: RpcBlockRequest, index: HexUInt64Field
    ) -> RpcEthTxResp | None:
        block = await self.get_block_by_tag(block_tag)
        if block.is_empty:
            return None
        elif not (neon_tx_meta := await self._db.get_tx_by_slot_tx_idx(block.slot, index)):
            return None
        return RpcEthTxResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getTransactionByBlockHashAndIndex")
    async def get_tx_by_block_hash_idx(
        self, block_hash: EthBlockHashField, index: HexUInt64Field
    ) -> RpcEthTxResp | None:
        block = await self._db.get_block_by_hash(block_hash)
        if block.is_empty:
            return None
        elif not (neon_tx_meta := await self._db.get_tx_by_slot_tx_idx(block.slot, index)):
            return None
        return RpcEthTxResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getBlockByNumber")
    async def get_block_by_number(
        self, ctx: HttpRequestCtx, block_tag: RpcBlockRequest, full: bool
    ) -> _RpcBlockResp | None:
        block = await self.get_block_by_tag(block_tag)
        if block.is_empty:
            return None
        return await self._fill_block(ctx, block, full)

    @NeonProxyApi.method(name="eth_getBlockByHash")
    async def get_block_by_hash(
        self, ctx: HttpRequestCtx, block_hash: EthBlockHashField, full: bool
    ) -> _RpcBlockResp | None:
        block = await self._db.get_block_by_hash(block_hash)
        if block.is_empty:
            return None
        return await self._fill_block(ctx, block, full)

    async def _fill_block(self, ctx: HttpRequestCtx, block: NeonBlockHdrModel, full: bool) -> _RpcBlockResp:
        tx_list = tuple()
        if block.commit != EthCommit.Pending:
            try:
                tx_list = await self._db.get_tx_list_by_slot(block.slot)
            except BaseException as exc:
                _LOG.error("error on loading txs from db", exc_info=exc, extra=self._msg_filter)

        # BaseFeePerGas for the block response is taken either from the mempool recent gas prices (for the recent block)
        #   - this case is used for requesting the current gas price by clients
        # or from the transactions inside that block (for the historical block).
        #   - for the indexing purposes
        _, token_gas_price = await self._get_token_gas_price(ctx)
        if block.commit in (EthCommit.Pending, EthCommit.Latest):
            # If block is pending, set baseFeePerGas to the current suggested token gas price.
            base_fee = token_gas_price.suggested_gas_price
        else:
            # Set base_fee as maximum from the block list before the block.
            chain_id = self._get_chain_id(ctx)
            block_list = await self._db.get_block_base_fee_list(chain_id, 128, block.slot)
            base_fee = max(block_list, key=lambda x: x.base_fee).base_fee if block_list else 0

        return _RpcBlockResp.from_raw(block, tx_list, full, base_fee)

    @NeonProxyApi.method(name="eth_getBlockTransactionCountByNumber")
    async def get_tx_cnt_by_block_number(self, block_tag: RpcBlockRequest) -> HexUIntField:
        block = await self.get_block_by_tag(block_tag)
        return await self._get_tx_cnt(block)

    @NeonProxyApi.method(name="eth_getBlockTransactionCountByHash")
    async def get_tx_cnt_by_block_hash(self, block_hash: EthBlockHashField) -> HexUIntField:
        block = await self._db.get_block_by_hash(block_hash)
        return await self._get_tx_cnt(block)

    async def _get_tx_cnt(self, block: NeonBlockHdrModel) -> int:
        if block.is_empty or (block.commit == EthCommit.Pending):
            return 0

        tx_list = await self._db.get_tx_list_by_slot(block.slot)
        return len(tx_list)

    @NeonProxyApi.method(name="eth_blockNumber")
    async def get_block_number(self) -> HexUIntField:
        return await self._db.get_latest_slot()

    @NeonProxyApi.method(name="neon_finalizedBlockNumber")
    async def get_finalized_block_number(self) -> HexUIntField:
        return await self._db.get_finalized_slot()

    @NeonProxyApi.method(name="neon_earliestBlockNumber")
    async def get_earliest_block_number(self) -> HexUIntField:
        return await self._db.get_earliest_slot()

    @NeonProxyApi.method(name="neon_getSolanaTransactionByNeonTransaction")
    async def get_solana_tx_list(
        self,
        tx_hash: EthTxHashField | SolTxSigField,
        full: bool = False,
    ) -> list[dict | SolTxSigField]:
        if not (tx_hash := await self._get_neon_tx_hash(tx_hash)):
            return list()

        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            return list()

        alt_sig_list = await self._db.get_alt_sig_list_by_neon_sig(tx_hash)
        sol_sig_list = await self._db.get_sol_tx_sig_list_by_neon_tx_hash(tx_hash)

        if not sol_sig_list:
            return list()

        rcpt_sol_tx_sig = neon_tx_meta.neon_tx_rcpt.sol_tx_sig
        sig_list: Sequence[SolTxSigSlotInfo] = self._sort_alt_sol_tx_list(alt_sig_list, sol_sig_list, rcpt_sol_tx_sig)
        sig_list: list[SolTxSig] = list(map(lambda x: x.sol_tx_sig, sig_list))
        if not full:
            return sig_list

        # if user requests not just signatures, but full SolanaTx body
        sol_tx_list = await self._sol_client.get_tx_list(sig_list, commit=SolCommit.Confirmed, json_format=True)
        try:
            result_list: list[dict | SolTxSig] = list()
            for sig, tx in zip(sig_list, sol_tx_list):
                if tx:
                    result_list.append(json.loads(tx.to_json()))
                else:
                    result_list.append(sig)
            return result_list

        except BaseException as exc:
            _LOG.warning("unexpected error on decode SolanaTx", exc_info=exc)

        return sig_list

    @NeonProxyApi.method(name="neon_getTransactionReceipt")
    async def get_neon_tx_receipt(
        self,
        tx_hash: EthTxHashField | SolTxSigField,
        detail: _RpcNeonTxReceiptDetailField = _RpcNeonTxReceiptDetail.SolTxList,
    ) -> _RpcNeonTxReceiptResp | _RpcEthTxReceiptResp | None:
        if not (tx_hash := await self._get_neon_tx_hash(tx_hash)):
            return None

        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            return None

        meta_list: Sequence[SolNeonTxIxMetaModel | SolNeonAltTxIxModel] = list()
        if detail == _RpcNeonTxReceiptDetail.SolTxList:
            alt_meta_list = await self._db.get_alt_ix_list_by_neon_tx_hash(tx_hash)
            sol_meta_list = await self._db.get_sol_ix_list_by_neon_tx_hash(tx_hash)
            if sol_meta_list:
                rcpt_sol_tx_sig = neon_tx_meta.neon_tx_rcpt.sol_tx_sig
                meta_list = self._sort_alt_sol_tx_list(alt_meta_list, sol_meta_list, rcpt_sol_tx_sig)

        return _RpcNeonTxReceiptResp.from_raw(neon_tx_meta, detail=detail, sol_meta_list=meta_list)

    @NeonProxyApi.method(name="neon_getPendingTransactions")
    async def get_tx_status_list(
        self,
        ctx: HttpRequestCtx,
        sender: EthNotNoneAddressField | SolNotNonePubKeyField,
    ) -> dict[HexUIntField, list[_RpcNeonTxStatusModel]]:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(sender, SolPubKey))
        sender_addr = NeonAddress.from_raw(sender, chain_id)
        sender_acct = await self._core_api_client.get_neon_account(sender_addr, None)
        resp = await self._mp_client.get_tx_status_list_by_sender(self._get_ctx_id(ctx), sender_acct)

        tree_dict: dict[int, NeonSkdTreeModel] = dict()

        async def _get_tree(_nonce: int) -> NeonSkdTreeModel:
            nonlocal tree_dict
            nonlocal sender_addr

            if _tree := tree_dict.get(_nonce, None):
                return _tree
            _tree = await self._core_api_client.get_neon_skd_tree(sender_addr, _nonce, None)
            tree_dict[_nonce] = _tree
            return _tree

        tx_status_list = resp.tx_status_list
        if not tx_status_list:
            tree = await _get_tree(sender_acct.state_tx_cnt)
            if tree.is_exist:
                node = tree.node_list[0]
                tx_status = MpTxStatusModel(
                    neon_tx_hash=node.neon_tx_hash,
                    nonce=sender_acct.state_tx_cnt,
                    exec_pct_list=list(),
                )
                tx_status_list = [tx_status]

        if not tx_status_list:
            return dict()

        def _get_status(_tx: MpTxStatusModel) -> _RpcNeonTxStatus:
            nonlocal resp

            if _tx.nonce > resp.state_tx_cnt:
                return _RpcNeonTxStatus.HighNonce
            elif _tx.nonce < resp.state_tx_cnt:
                return _RpcNeonTxStatus.Done
            elif resp.in_processing:
                return _RpcNeonTxStatus.InProgress
            elif _tx.gas_price < resp.min_exec_gas_price:
                return _RpcNeonTxStatus.LowGasPrice
            elif _tx.cost < resp.balance:
                return _RpcNeonTxStatus.InsufficientBalance
            return _RpcNeonTxStatus.NotStarted

        async def _get_status_pct(
            _tx: MpTxStatusModel, _tree: NeonSkdTreeModel, idx: int
        ) -> tuple[_RpcNeonTxStatus, int]:
            if not _tree.is_exist:
                return _get_status(_tx), _tx.get_exec_pct(_tx.neon_tx_hash)

            _node = _tree.node_list[idx]
            _status = _tree.get_neon_skd_status(idx)
            if _status in (_status.Success, _status.Failed):
                return _RpcNeonTxStatus.Done, 100
            elif _status == _status.Skipped:
                return _RpcNeonTxStatus.Skipped, 100
            elif _status == _status.InProgress:
                return _RpcNeonTxStatus.InProgress, _tx.get_exec_pct(_node.neon_tx_hash)
            elif _status == _status.NotStarted:
                return _RpcNeonTxStatus.WaitForParentTx, 0

            _skd_tx = await self._db.get_neon_skd_tx_by_hash(_node.neon_tx_hash)

            if (not _skd_tx) or (not _skd_tx.rlp_tx):
                return _RpcNeonTxStatus.NoTxBody, 0
            elif idx == 0:
                return _get_status(_tx), _tx.get_exec_pct(_tx.neon_tx_hash)

            return _RpcNeonTxStatus.NotStarted, 0

        async def _new_tx_status(_tx: MpTxStatusModel, _tree: NeonSkdTreeModel, idx: int) -> _RpcNeonTxStatusModel:
            if not _tree.is_exist:
                status, exec_pct, tx_hash = _RpcNeonTxStatus.Done, _tx.get_exec_pct(_tx.neon_tx_hash), _tx.neon_tx_hash
            else:
                tx_hash = _tree.node_list[idx].neon_tx_hash
                status, exec_pct = await _get_status_pct(_tx, _tree, idx)

            return _RpcNeonTxStatusModel(txHash=tx_hash, status=status, executionPercentage=exec_pct, age=_tx.age_sec)

        async def _new_tx_status_list(_tx: MpTxStatusModel) -> list[_RpcNeonTxStatusModel]:
            _tree = await _get_tree(_tx.nonce)
            return [(await _new_tx_status(_tx, _tree, idx)) for idx in range(max(len(_tree.node_list), 1))]

        return {tx.nonce: await _new_tx_status_list(tx) for tx in tx_status_list}

    @NeonProxyApi.method(name="neon_getScheduledTreeAccount")
    async def get_neon_skd_tree(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField | SolNotNonePubKeyField,
        nonce: HexUIntField,
        block_tag: RpcBlockRequest,
    ) -> _RpcNeonTreeAccountResp | None:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(address, SolPubKey))
        block = await self.get_block_by_tag(block_tag)
        addr = NeonAddress.from_raw(address, chain_id)

        tree_acct = await self._core_api_client.get_neon_skd_tree(addr, nonce, block)
        if not tree_acct.is_exist:
            return None
        return _RpcNeonTreeAccountResp.from_raw(tree_acct, nonce)

    @staticmethod
    def _sort_alt_sol_tx_list(alt_meta_list: Sequence, sol_meta_list: Sequence, rcpt_sol_tx_sig: SolTxSig) -> list[Any]:
        # signatures with Neon-Receipt (or Solana-Fail + Neon-Cancel) should be at the end of the list,
        #   because it simplifies the user experience
        if (pos := next((idx for idx, v in enumerate(sol_meta_list) if v.sol_tx_sig == rcpt_sol_tx_sig), -1)) == -1:
            last_pos = -2 if len(sol_meta_list) > 1 else -1
            sol_meta_iter, last_meta_list = iter(sol_meta_list[:last_pos]), sol_meta_list[last_pos:]
        else:
            sol_meta_list = list(sol_meta_list)
            last_meta_list = list()
            last_meta_list.append(sol_meta_list.pop(pos))
            if pos > 0:
                last_meta_list.insert(0, sol_meta_list.pop(pos - 1))
            sol_meta_iter = iter(sol_meta_list)

        alt_meta_iter = iter(alt_meta_list)

        # The result list is sorted by a slot :
        #   1. Prepare transactions
        #      - ALT transactions (Create and Extend)
        #      - Neon transaction (WriteToHolder)
        #   2. Neon execution
        #   3. ALT transaction
        #      - Deactivate
        #      - Close
        #   4. Finalization
        #      - Neon-Receipt
        #      - (or) Solana-Fail + Neon-Cancel

        result_list = list()
        sol_meta, alt_meta = next(sol_meta_iter, None), next(alt_meta_iter, None)
        while sol_meta or alt_meta:
            if alt_meta:
                if sol_meta and sol_meta.slot < alt_meta.slot:
                    result_list.append(sol_meta)
                    sol_meta = next(sol_meta_iter, None)
                else:
                    result_list.append(alt_meta)
                    alt_meta = next(alt_meta_iter, None)
            elif sol_meta:
                result_list.append(sol_meta)
                sol_meta = next(sol_meta_iter, None)

        # Last step: add Neon-Receipt or (Solana-Fail + Neon-Cancel)
        result_list.extend(last_meta_list)
        return result_list

    async def _get_neon_tx_hash(self, tx_hash: EthTxHash | SolTxSig) -> EthTxHash:
        if isinstance(tx_hash, EthTxHash):
            return tx_hash

        return await self._db.get_neon_tx_hash_by_sol_tx_sig(tx_hash)

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import ClassVar, Final, Annotated, Literal

from pydantic import Field, PlainValidator
from strenum import StrEnum
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.commit_level import EthCommit
from common.ethereum.hash import (
    EthTxHashField,
    EthAddressField,
    EthBlockHashField,
    EthHash32Field,
    EthZeroAddressField,
    EthAddress,
)
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonEvmIxCode
from common.neon.transaction_decoder import SolNeonAltIxModel, SolNeonTxIxMetaModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel
from common.solana.alt_program import SolAltIxCode
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKeyField, SolPubKey
from common.solana.signature import SolTxSigField, SolTxSig
from common.utils.pydantic import HexUIntField, HexUInt256Field, HexUInt8Field, Base58Field
from .api import RpcBlockRequest, RpcEthTxEventModel, RpcNeonTxEventModel
from .server_abc import NeonProxyApi

_LOG = logging.getLogger(__name__)


class _RpcNeonTxReceiptDetail(StrEnum):
    Eth = "ethereum"
    Neon = "neon"
    SolTxList = "solanaTransactionList"

    @classmethod
    def from_raw(cls, tag: str | _RpcNeonTxReceiptDetail) -> Self:
        if isinstance(tag, _RpcNeonTxReceiptDetail):
            return tag

        try:
            return cls(tag)
        except (BaseException,):
            raise ValueError(f"Should be one of: {cls.Neon}, {cls.Eth}, {cls.SolTxList}")


_RpcNeonTxReceiptDetailField = Annotated[_RpcNeonTxReceiptDetail, PlainValidator(_RpcNeonTxReceiptDetail.from_raw)]


class _RpcTxResp(BaseJsonRpcModel):
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
    status: HexUIntField
    logsBloom: HexUInt256Field
    logs: tuple[RpcNeonTxEventModel | RpcEthTxEventModel, ...]

    @classmethod
    def from_raw(cls, neon_tx_meta: NeonTxMetaModel) -> Self:
        rcpt = neon_tx_meta.neon_tx_rcpt
        return cls(
            **cls._to_dict(neon_tx_meta),
            logs=tuple([RpcEthTxEventModel.from_raw(e) for e in rcpt.event_list if not e.is_hidden]),
        )

    @staticmethod
    def _to_dict(neon_tx_meta: NeonTxMetaModel) -> dict:
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
            effectiveGasPrice=tx.gas_price,
            gasUsed=rcpt.total_gas_used,
            cumulativeGasUsed=rcpt.sum_gas_used,
            contractAddress=tx.contract,
            status=rcpt.status,
            logsBloom=rcpt.log_bloom,
        )


class _RpcNeonCostModel(BaseJsonRpcModel):
    neonOperatorAddress: SolPubKeyField
    solanaLamportsSpent: int
    neonAlanIncome: int


@dataclass
class _RpcNeonCostDraft:
    neonOperatorAddress: SolPubKeyField
    solanaLamportsSpent: int = 0
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
    neonInstructionCode: HexUIntField
    neonInstructionName: str
    neonEvmSteps: int
    neonTotalEvmSteps: int
    neonGasUsed: int
    neonTotalGasUsed: int
    neonAlanIncome: int
    neonMiner: EthAddressField
    neonLogs: tuple[RpcNeonTxEventModel, ...]

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
        neon_income = ix_meta.neon_gas_used * tx.gas_price

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
            neonAlanIncome=neon_income,
            neonMiner=ix_meta.neon_tx_ix_miner,
            neonLogs=tuple(log_list),
        )


class _RpcAltIxModel(BaseJsonRpcModel):
    solanaProgram: Literal["AddressLookupTable"] = "AddressLookupTable"
    solanaInstructionIndex: int
    solanaInnerInstructionIndex: int | None
    lookupTableInstructionCode: int
    lookupTableInstructionName: str
    lookupTableAddress: SolPubKeyField

    @classmethod
    def from_raw(cls, raw: SolNeonAltIxModel) -> Self:
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
    solanaLamportsSpent: int
    neonOperatorAddress: SolPubKeyField
    solanaInstructions: list[_RpcNeonIxModel | _RpcAltIxModel]


@dataclass
class _RpcSolReceiptDraft:
    solanaTransactionSignature: SolTxSig
    solanaTransactionIsSuccess: bool
    solanaBlockSlot: int
    solanaLamportsSpent: int
    neonOperatorAddress: SolPubKey
    solanaInstructions: list[_RpcNeonIxModel | _RpcAltIxModel]

    @classmethod
    def from_raw(cls, raw: SolNeonAltIxModel | SolNeonTxIxMetaModel) -> Self:
        return cls(
            solanaTransactionSignature=raw.sol_tx_sig,
            solanaTransactionIsSuccess=raw.is_success,
            solanaBlockSlot=raw.slot,
            solanaLamportsSpent=raw.sol_tx_cost.sol_spent,
            neonOperatorAddress=raw.sol_tx_cost.sol_signer,
            solanaInstructions=list(),
        )

    def to_clean_copy(self) -> _RpcSolReceiptModel:
        return _RpcSolReceiptModel.model_validate(self, from_attributes=True)


class _RpcNeonTxReceiptResp(_RpcEthTxReceiptResp):
    solanaBlockHash: Base58Field
    solanaCompleteTransactionSignature: SolTxSigField
    solanaCompleteInstructionIndex: int
    solanaCompleteInnerInstructionIndex: int | None
    neonRawTransaction: EthBinStrField
    neonIsCompleted: bool
    neonIsCanceled: bool
    solanaTransactions: tuple[_RpcSolReceiptModel, ...]
    neonCosts: tuple[_RpcNeonCostModel, ...]

    @classmethod
    def from_raw(
        cls,
        neon_tx_meta: NeonTxMetaModel,
        *,
        detail: _RpcNeonTxReceiptDetail = _RpcNeonTxReceiptDetail.Eth,
        sol_meta_list: tuple[SolNeonTxIxMetaModel, ...] = tuple(),
        alt_meta_list: tuple[SolNeonAltIxModel, ...] = tuple(),
    ) -> _RpcEthTxReceiptResp | Self:
        if detail == _RpcNeonTxReceiptDetail.Eth:
            return _RpcEthTxReceiptResp.from_raw(neon_tx_meta)

        tx = neon_tx_meta.neon_tx
        rcpt = neon_tx_meta.neon_tx_rcpt
        if detail == _RpcNeonTxReceiptDetail.Neon:
            log_list = tuple([RpcNeonTxEventModel.from_raw(e) for e in rcpt.event_list])
            sol_tx_list, neon_cost_list = tuple(), tuple()
        else:
            log_list = tuple()
            sol_tx_list, neon_cost_list = cls._to_sol_receipt_list(neon_tx_meta, sol_meta_list, alt_meta_list)

        return cls(
            **cls._to_dict(neon_tx_meta),
            solanaBlockHash=rcpt.block_hash.to_bytes(),
            solanaCompleteTransactionSignature=rcpt.sol_tx_sig,
            solanaCompleteInstructionIndex=rcpt.sol_ix_idx,
            solanaCompleteInnerInstructionIndex=rcpt.sol_inner_ix_idx,
            neonRawTransaction=tx.to_rlp_tx(),
            neonIsCompleted=rcpt.is_completed,
            neonIsCanceled=rcpt.is_canceled,
            logs=log_list,
            solanaTransactions=sol_tx_list,
            neonCosts=neon_cost_list,
        )

    @staticmethod
    def _to_sol_receipt_list(
        neon_tx_meta: NeonTxMetaModel,
        sol_meta_list: tuple[SolNeonTxIxMetaModel, ...],
        alt_meta_list: tuple[SolNeonAltIxModel, ...],
    ) -> tuple[tuple[_RpcSolReceiptModel, ...], tuple[_RpcNeonCostModel, ...]]:
        rcpt_list: list[_RpcSolReceiptModel] = list()
        cost_dict: dict[SolPubKey, _RpcNeonCostDraft] = dict()
        cost: _RpcNeonCostDraft | None = None
        rcpt: _RpcSolReceiptDraft | None = None

        def _update_list(_ix_meta: SolNeonTxIxMetaModel | SolNeonAltIxModel) -> None:
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

                rcpt_cost.solanaLamportsSpent += _ix_meta.sol_tx_cost.sol_spent
                cost = rcpt_cost

        def _add_neon_ix(_ix_meta: SolNeonTxIxMetaModel) -> None:
            _update_list(_ix_meta)
            ix = _RpcNeonIxModel.from_raw(neon_tx_meta, _ix_meta)
            rcpt.solanaInstructions.append(ix)
            cost.neonAlanIncome += ix.neonAlanIncome

        # logic of ordering is the same with neon_getSolanaTransactionByNeonTransaction

        last_pos = -2 if len(sol_meta_list) > 1 else -1
        sol_meta_iter, last_meta_list = iter(sol_meta_list[:last_pos]), sol_meta_list[last_pos:]
        alt_meta_iter = iter(alt_meta_list)

        sol_meta, alt_meta = next(sol_meta_iter, None), next(alt_meta_iter, None)
        while sol_meta or alt_meta:
            if alt_meta:
                if sol_meta and sol_meta.slot < alt_meta.slot:
                    _add_neon_ix(sol_meta)
                    sol_meta = next(sol_meta_iter, None)
                else:
                    _update_list(alt_meta)
                    rcpt.solanaInstructions.append(_RpcAltIxModel.from_raw(alt_meta))
                    alt_meta = next(alt_meta_iter, None)
            elif sol_meta:
                _add_neon_ix(sol_meta)
                sol_meta = next(sol_meta_iter, None)

        for sol_meta in last_meta_list:
            _add_neon_ix(sol_meta)

        if rcpt:
            rcpt_list.append(rcpt.to_clean_copy())

        cost_list = tuple(map(lambda x: x.to_clean_copy(), iter(cost_dict.values())))
        return tuple(rcpt_list), cost_list


class _RpcBlockResp(BaseJsonRpcModel):
    logsBloom: HexUInt256Field

    transactionsRoot: EthHash32Field
    receiptsRoot: EthHash32Field
    stateRoot: EthHash32Field

    uncles: tuple[EthHash32Field, ...]
    sha3Uncles: EthHash32Field

    difficulty: HexUIntField
    totalDifficulty: HexUIntField
    extraData: EthBinStrField
    miner: EthZeroAddressField | None
    nonce: HexUInt8Field | None
    mixHash: EthHash32Field
    size: HexUIntField

    gasLimit: HexUIntField
    gasUsed: HexUIntField
    blockHash: EthBlockHashField | None = Field(serialization_alias="hash")
    number: HexUIntField
    parentHash: EthBlockHashField
    timestamp: HexUIntField
    transactions: tuple[_RpcTxResp | EthTxHashField, ...]

    _fake_hash: Final[EthHash32Field] = "0x" + "00" * 31 + "01"
    _empty_root: Final[EthHash32Field] = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    _sha3uncle_hash: Final[EthHash32Field] = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

    @classmethod
    def from_raw(cls, block: NeonBlockHdrModel, tx_list: tuple[NeonTxMetaModel, ...], full: bool) -> Self:
        is_pending = block.commit == EthCommit.Pending

        total_gas_used = 0
        log_bloom = 0
        rpc_tx_list: list[_RpcTxResp | EthTxHashField] = list()

        if not is_pending:
            block_hash = block.block_hash
            miner = EthAddress.default()
            nonce = 0
            for tx in tx_list:
                total_gas_used = max(tx.neon_tx_rcpt.sum_gas_used, total_gas_used)
                log_bloom |= tx.neon_tx_rcpt.log_bloom
                rpc_tx_list.append(_RpcTxResp.from_raw(tx) if full else tx.neon_tx_hash)
        else:
            block_hash = None
            miner = None
            nonce = None

        return cls(
            logsBloom=log_bloom,
            transactionsRoot=cls._fake_hash if tx_list else cls._empty_root,
            receiptsRoot=cls._fake_hash,
            stateRoot=cls._fake_hash,
            #
            uncles=tuple(),
            sha3Uncles=cls._sha3uncle_hash,
            difficulty=0,
            totalDifficulty=0,
            extraData=b"",
            mixHash=cls._fake_hash,
            size=1,
            #
            gasLimit=max(48_000_000_000_000, total_gas_used),
            gasUsed=total_gas_used,
            number=block.slot,
            parentHash=block.parent_block_hash,
            timestamp=block.block_time,
            #
            miner=miner,
            nonce=nonce,
            blockHash=block_hash,
            transactions=tuple(rpc_tx_list),
        )


class NpBlockTxApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::BlockTransaction"

    @NeonProxyApi.method(name="eth_getTransactionByHash")
    async def get_tx_by_hash(self, ctx: HttpRequestCtx, neon_tx_hash: EthTxHashField) -> _RpcTxResp | None:
        if not (meta := await self._db.get_tx_by_neon_tx_hash(neon_tx_hash)):
            if not (meta := await self._mp_client.get_tx_by_hash(self.get_ctx_id(ctx), neon_tx_hash)):
                return None
        return _RpcTxResp.from_raw(meta)

    @NeonProxyApi.method(name="neon_getTransactionBySenderNonce")
    async def get_tx_by_sender_nonce(
        self,
        ctx: HttpRequestCtx,
        sender: EthAddressField,
        nonce: HexUIntField,
    ) -> _RpcTxResp | None:
        neon_acct = NeonAccount.from_raw(sender, self.get_chain_id(ctx))
        inc_no_chain_id = True if self.is_default_chain_id(ctx) else False
        if not (meta := await self._db.get_tx_by_sender_nonce(neon_acct, nonce, inc_no_chain_id)):
            if not (meta := await self._mp_client.get_tx_by_sender_nonce(self.get_ctx_id(ctx), neon_acct, nonce)):
                return None
        return _RpcTxResp.from_raw(meta)

    @NeonProxyApi.method(name="eth_getTransactionReceipt")
    async def get_tx_receipt(self, neon_tx_hash: EthTxHashField) -> _RpcEthTxReceiptResp | None:
        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(neon_tx_hash)):
            return None
        return _RpcEthTxReceiptResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getTransactionByBlockNumberAndIndex")
    async def get_tx_by_block_number_idx(self, block_tag: RpcBlockRequest, index: HexUIntField) -> _RpcTxResp | None:
        block = await self.get_block_by_tag(block_tag)
        if block.is_empty:
            return None
        elif not (neon_tx_meta := await self._db.get_tx_by_slot_tx_idx(block.slot, index)):
            return None
        return _RpcTxResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getTransactionByBlockHashAndIndex")
    async def get_tx_by_block_hash_idx(self, block_hash: EthBlockHashField, index: HexUIntField) -> _RpcTxResp | None:
        block = await self._db.get_block_by_hash(block_hash)
        if block.is_empty:
            return None
        elif not (neon_tx_meta := await self._db.get_tx_by_slot_tx_idx(block.slot, index)):
            return None
        return _RpcTxResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="eth_getBlockByNumber")
    async def get_block_by_number(self, block_tag: RpcBlockRequest, full: bool) -> _RpcBlockResp | None:
        block = await self.get_block_by_tag(block_tag)
        if block.is_empty:
            return None
        return await self._fill_block(block, full)

    @NeonProxyApi.method(name="eth_getBlockByHash")
    async def get_block_by_hash(self, block_hash: EthBlockHashField, full: bool) -> _RpcBlockResp | None:
        block = await self._db.get_block_by_hash(block_hash)
        if block.is_empty:
            return None
        return await self._fill_block(block, full)

    async def _fill_block(self, block: NeonBlockHdrModel, full: bool) -> _RpcBlockResp:
        tx_list = tuple()
        if block.commit != EthCommit.Pending:
            tx_list = await self._db.get_tx_list_by_slot(block.slot)
        return _RpcBlockResp.from_raw(block, tx_list, full)

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
    async def get_solana_tx_list(self, tx_hash: EthTxHashField, full: bool = False) -> list[dict | SolTxSigField]:
        alt_sig_list = await self._db.get_alt_sig_list_by_neon_sig(tx_hash)
        neon_sig_list = await self._db.get_sol_tx_sig_list_by_neon_tx_hash(tx_hash)

        if not neon_sig_list:
            return list()

        last_pos = -2 if len(neon_sig_list) > 1 else -1
        # last 2 signatures (Neon-Receipt or (Solana-Fail + Neon-Cancel)) should be at the end of the list,
        #   because it simplifies the user experience
        neon_sig_iter, last_sig_list = iter(neon_sig_list[:last_pos]), neon_sig_list[last_pos:]
        alt_sig_iter = iter(alt_sig_list)

        # Result list is sorted by slot :
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

        sig_list: list[SolTxSig] = list()
        neon_sig, alt_sig = next(neon_sig_iter, None), next(alt_sig_iter, None)
        while neon_sig or alt_sig:
            if alt_sig:
                if neon_sig and neon_sig[0] < alt_sig[0]:
                    sig_list.append(neon_sig[1])
                    neon_sig = next(neon_sig_iter, None)
                else:
                    sig_list.append(alt_sig[1])
                    alt_sig = next(alt_sig_iter, None)
            elif neon_sig:
                sig_list.append(neon_sig[1])
                neon_sig = next(neon_sig_iter, None)

        # Last step: add Neon-Receipt or (Solana-Fail + Neon-Cancel)
        sig_list.extend(map(lambda x: x[1], last_sig_list))
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
        neon_tx_hash: EthTxHashField,
        detail: _RpcNeonTxReceiptDetailField,
    ) -> _RpcNeonTxReceiptResp | _RpcEthTxReceiptResp | None:
        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(neon_tx_hash)):
            return None

        alt_meta_list: tuple[SolNeonAltIxModel, ...] = tuple()
        sol_meta_list: tuple[SolNeonTxIxMetaModel, ...] = tuple()
        if detail == _RpcNeonTxReceiptDetail.SolTxList:
            alt_meta_list = await self._db.get_alt_ix_list_by_neon_tx_hash(neon_tx_hash)
            sol_meta_list = await self._db.get_sol_ix_list_by_neon_tx_hash(neon_tx_hash)
        return _RpcNeonTxReceiptResp.from_raw(
            neon_tx_meta,
            detail=detail,
            alt_meta_list=alt_meta_list,
            sol_meta_list=sol_meta_list,
        )

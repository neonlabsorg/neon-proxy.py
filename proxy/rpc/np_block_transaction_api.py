from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import ClassVar, Final, Annotated, Literal, Any, Sequence

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
    EthNotNoneAddressField,
)
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonEvmIxCode
from common.neon.transaction_decoder import SolNeonAltTxIxModel, SolNeonTxIxMetaModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKeyField, SolPubKey
from common.solana.signature import SolTxSigField, SolTxSig, SolTxSigSlotInfo
from common.utils.pydantic import HexUIntField, Hex256UIntField, Hex8UIntField, Base58Field, HexUInt64Field
from .api import RpcBlockRequest, RpcEthTxEventModel, RpcNeonTxEventModel
from .server_abc import NeonProxyApi
from ..base.rpc_api import RpcEthTxResp

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
    logsBloom: Hex256UIntField
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
            effectiveGasPrice=neon_tx_meta.effective_gas_price,
            gasUsed=rcpt.total_gas_used,
            cumulativeGasUsed=rcpt.sum_gas_used,
            contractAddress=tx.contract,
            status=rcpt.status,
            logsBloom=rcpt.log_bloom,
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
        neon_tx_fee = ix_meta.neon_gas_used * tx.gas_price

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
            neonTransactionFee=neon_tx_fee,
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
        sol_meta_list: tuple[SolNeonTxIxMetaModel | SolNeonAltTxIxModel, ...] = tuple(),
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
            sol_tx_list, neon_cost_list = cls._to_sol_receipt_list(neon_tx_meta, sol_meta_list)

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
        sol_meta_list: tuple[SolNeonTxIxMetaModel | SolNeonAltTxIxModel, ...],
    ) -> tuple[tuple[_RpcSolReceiptModel, ...], tuple[_RpcNeonCostModel, ...]]:
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

        cost_list = tuple(map(lambda x: x.to_clean_copy(), iter(cost_dict.values())))
        return tuple(rcpt_list), cost_list


class _RpcBlockResp(BaseJsonRpcModel):
    logsBloom: Hex256UIntField

    transactionsRoot: EthHash32Field
    receiptsRoot: EthHash32Field
    stateRoot: EthHash32Field

    uncles: tuple[EthHash32Field, ...]
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
    transactions: tuple[RpcEthTxResp | EthTxHashField, ...]

    _fake_hash: Final[EthHash32Field] = "0x" + "00" * 31 + "01"
    _empty_root: Final[EthHash32Field] = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    _sha3uncle_hash: Final[EthHash32Field] = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

    @classmethod
    def from_raw(
        cls,
        block: NeonBlockHdrModel,
        tx_list: tuple[NeonTxMetaModel, ...],
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
            baseFeePerGas=base_fee_per_gas,
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
    async def get_tx_by_hash(self, ctx: HttpRequestCtx, tx_hash: EthTxHashField) -> RpcEthTxResp | None:
        if not (meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            if not (meta := await self._mp_client.get_tx_by_hash(self._get_ctx_id(ctx), tx_hash)):
                return None
        return RpcEthTxResp.from_raw(meta)

    @NeonProxyApi.method(name="neon_getTransactionBySenderNonce")
    async def get_tx_by_sender_nonce(
        self,
        ctx: HttpRequestCtx,
        sender: EthNotNoneAddressField,
        nonce: HexUInt64Field,
    ) -> RpcEthTxResp | None:
        neon_acct = NeonAccount.from_raw(sender, self._get_chain_id(ctx))
        inc_no_chain_id = True if self._is_default_chain_id(ctx) else False
        if not (meta := await self._db.get_tx_by_sender_nonce(neon_acct, nonce, inc_no_chain_id)):
            if not (meta := await self._mp_client.get_tx_by_sender_nonce(self._get_ctx_id(ctx), neon_acct, nonce)):
                return None
        return RpcEthTxResp.from_raw(meta)

    @NeonProxyApi.method(name="eth_getTransactionReceipt")
    async def get_tx_receipt(self, tx_hash: EthTxHashField) -> _RpcEthTxReceiptResp | None:
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
                _LOG.debug("error on loading txs", exc_info=exc, extra=self._msg_filter)

        # BaseFeePerGas for the block response is taken either from the mempool recent gas prices (for the recent block)
        #   - this case is used for requesting the current gas price by clients
        # or from the transactions inside that block (for the historical block).
        #   - for the indexing purposes
        latest_slot: int = await self._db.get_latest_slot()
        _, token_gas_price = await self._get_token_gas_price(ctx)
        if block.slot > latest_slot:
            # If block is pending, set baseFeePerGas to the current suggested token gas price.
            base_fee = token_gas_price.suggested_gas_price
        else:
            # Try recent mempool gas prices.
            base_fee = token_gas_price.find_gas_price(block.slot)

        # Recent gas prices from the mempool is lacking the data, we have to take it from the transaction list.
        if base_fee is None:
            # Set base_fee as maximum from the block list before the block.
            chain_id = self._get_chain_id(ctx)
            block_list = await self._db.get_block_base_fee_list(chain_id, 128, latest_slot)
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
        tx_hash: EthTxHashField,
        full: bool = False,
    ) -> list[dict | SolTxSigField]:
        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            return list()

        alt_sig_list = await self._db.get_alt_sig_list_by_neon_sig(tx_hash)
        sol_sig_list = await self._db.get_sol_tx_sig_list_by_neon_tx_hash(tx_hash)

        if not sol_sig_list:
            return list()

        rcpt_sol_tx_sig = neon_tx_meta.neon_tx_rcpt.sol_tx_sig
        sig_list: tuple[SolTxSigSlotInfo, ...] = self._sort_alt_sol_tx_list(alt_sig_list, sol_sig_list, rcpt_sol_tx_sig)
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
        tx_hash: EthTxHashField,
        detail: _RpcNeonTxReceiptDetailField = _RpcNeonTxReceiptDetail.SolTxList,
    ) -> _RpcNeonTxReceiptResp | _RpcEthTxReceiptResp | None:
        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash)):
            return None

        meta_list: tuple[SolNeonTxIxMetaModel | SolNeonAltTxIxModel, ...] = tuple()
        if detail == _RpcNeonTxReceiptDetail.SolTxList:
            alt_meta_list = await self._db.get_alt_ix_list_by_neon_tx_hash(tx_hash)
            sol_meta_list = await self._db.get_sol_ix_list_by_neon_tx_hash(tx_hash)
            if sol_meta_list:
                rcpt_sol_tx_sig = neon_tx_meta.neon_tx_rcpt.sol_tx_sig
                meta_list = self._sort_alt_sol_tx_list(alt_meta_list, sol_meta_list, rcpt_sol_tx_sig)

        return _RpcNeonTxReceiptResp.from_raw(neon_tx_meta, detail=detail, sol_meta_list=meta_list)

    @staticmethod
    def _sort_alt_sol_tx_list(
        alt_meta_list: Sequence, sol_meta_list: Sequence, rcpt_sol_tx_sig: SolTxSig
    ) -> tuple[Any, ...]:
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
        return tuple(result_list)

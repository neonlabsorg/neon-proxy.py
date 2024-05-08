from __future__ import annotations

from typing import ClassVar, Final

from pydantic import Field
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
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonTxModel
from common.utils.pydantic import HexUIntField, HexUInt256Field, HexUInt8Field
from .api import RpcBlockRequest, RpcEthTxEventModel
from .server_abc import NeonProxyApi


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


class _RpcTxReceiptResp(BaseJsonRpcModel):
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
    logs: tuple[RpcEthTxEventModel, ...]

    @classmethod
    def from_raw(cls, neon_tx_meta: NeonTxMetaModel) -> Self:
        tx = neon_tx_meta.neon_tx
        rcpt = neon_tx_meta.neon_tx_rcpt
        return cls(
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
            logs=tuple([RpcEthTxEventModel.from_raw(e) for e in rcpt.event_list if not e.is_hidden]),
        )


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
        self, ctx: HttpRequestCtx, sender: EthTxHashField, nonce: HexUIntField
    ) -> _RpcTxResp | None:
        neon_acct = NeonAccount(sender, self.get_chain_id(ctx))
        chain_id = None if self.is_default_chain_id(ctx) else neon_acct.chain_id
        if not (meta := await self._db.get_tx_by_sender_nonce(sender, nonce, chain_id)):
            if not (meta := await self._mp_client.get_tx_by_sender_nonce(self.get_ctx_id(ctx), sender, nonce)):
                return None
        return _RpcTxResp.from_raw(meta)

    @NeonProxyApi.method(name="eth_getTransactionReceipt")
    async def get_tx_receipt(self, neon_tx_hash: EthTxHashField) -> _RpcTxReceiptResp | None:
        if not (neon_tx_meta := await self._db.get_tx_by_neon_tx_hash(neon_tx_hash)):
            return None
        return _RpcTxReceiptResp.from_raw(neon_tx_meta)

    @NeonProxyApi.method(name="neon_getTransactionReceipt")
    def get_neon_tx_receipt(self) -> str:
        return "neon_getTransactionReceipt"

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
        return self._get_tx_cnt(block)

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
        return await self._db.get_earliest_block()

from __future__ import annotations

import logging
from typing import ClassVar

from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.commit_level import EthCommit
from common.ethereum.hash import EthAddress, EthZeroHash32Field, EthNotNoneAddressField
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.address import NeonAddress
from common.neon_rpc.api import NeonAccountModel
from common.solana.pubkey import SolPubKeyField, SolPubKey, SolNotNonePubKeyField
from common.utils.pydantic import HexUIntField
from .api import RpcBlockRequest
from .server_abc import NeonProxyApi

_LOG = logging.getLogger(__name__)


class _NeonRpcAccountResp(BaseJsonRpcModel):
    status: str
    address: EthNotNoneAddressField
    transactionCount: HexUIntField
    balance: HexUIntField
    chainId: HexUIntField
    solanaAddress: SolPubKeyField
    contractSolanaAddress: SolPubKeyField
    userPublicKey: SolPubKeyField

    @classmethod
    def from_raw(cls, raw: _NeonRpcAccountResp | NeonAccountModel) -> Self:
        if isinstance(raw, _NeonRpcAccountResp):
            return raw
        return cls(
            status=raw.status,
            address=raw.neon_address.eth_address,
            transactionCount=raw.state_tx_cnt,
            balance=raw.balance,
            chainId=raw.chain_id,
            solanaAddress=raw.sol_address,
            contractSolanaAddress=raw.contract_sol_address,
            userPublicKey=raw.user_sol_address,
        )


class NpAccountApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::Account"

    @NeonProxyApi.method(name="eth_getTransactionCount")
    async def get_tx_cnt(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField | SolNotNonePubKeyField,
        block_tag: RpcBlockRequest,
    ) -> HexUIntField:
        if isinstance(address, SolPubKey):
            self._validate_layer0_chain_id(ctx)

        block = await self.get_block_by_tag(block_tag)
        chain_id = self._get_chain_id(ctx)
        addr = NeonAddress.from_raw(address, chain_id)

        mp_tx_nonce: int | None = None
        if block.commit == EthCommit.Pending:
            mp_tx_nonce = await self._mp_client.get_pending_tx_cnt(self._get_ctx_id(ctx), addr)
            # _LOG.debug("pending tx count for %s is %s", addr, mp_tx_nonce)

        tx_cnt = await self._core_api_client.get_state_tx_cnt(addr, block)
        return max(tx_cnt, mp_tx_nonce or 0)

    @NeonProxyApi.method(name="eth_getBalance")
    async def get_balance(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField | SolNotNonePubKeyField,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        if isinstance(address, SolPubKey):
            self._validate_layer0_chain_id(ctx)

        chain_id = self._get_chain_id(ctx)
        block = await self.get_block_by_tag(block_tag)
        acct = await self._core_api_client.get_neon_account(NeonAddress.from_raw(address, chain_id), block)

        # custom case for Metamask: allow fee-less txs from accounts without balance
        if not acct.balance:
            if await self._has_fee_less_tx_permit(ctx, address, EthAddress.default(), acct.state_tx_cnt, 0):
                return 1

        return acct.balance

    @NeonProxyApi.method(name="eth_getCode")
    async def get_code(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField,
        block_tag: RpcBlockRequest,
    ) -> EthBinStrField:
        block = await self.get_block_by_tag(block_tag)
        chain_id = self._get_chain_id(ctx)
        neon_addr = NeonAddress.from_raw(address, chain_id)
        resp = await self._core_api_client.get_neon_contract(neon_addr, block)
        return resp.code

    @NeonProxyApi.method(name="eth_getStorageAt")
    async def get_storage_at(
        self,
        address: EthNotNoneAddressField,
        position: HexUIntField,
        block_tag: RpcBlockRequest,
    ) -> EthZeroHash32Field:
        block = await self.get_block_by_tag(block_tag)
        return await self._core_api_client.get_storage_at(address, position, block)

    @NeonProxyApi.method(name="neon_getAccount")
    async def get_neon_account(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField | SolNotNonePubKeyField,
        block_tag: RpcBlockRequest,
    ) -> _NeonRpcAccountResp:
        if isinstance(address, SolPubKey):
            self._validate_layer0_chain_id(ctx)

        block = await self.get_block_by_tag(block_tag)
        chain_id = self._get_chain_id(ctx)
        addr = NeonAddress.from_raw(address, chain_id)

        resp = await self._core_api_client.get_neon_account(addr, block)
        return _NeonRpcAccountResp.from_raw(resp)

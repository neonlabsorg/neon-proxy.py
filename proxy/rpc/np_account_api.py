from __future__ import annotations

import logging
from typing import ClassVar

from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.commit_level import EthCommit
from common.ethereum.hash import EthAddress, EthZeroHash32Field, EthNotNoneAddressField
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.neon_rpc.api import NeonAccountModel
from common.solana.pubkey import SolPubKeyField
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

    @classmethod
    def from_raw(cls, raw: _NeonRpcAccountResp | NeonAccountModel) -> Self:
        if isinstance(raw, _NeonRpcAccountResp):
            return raw
        return cls(
            status=raw.status,
            address=raw.account.eth_address,
            transactionCount=raw.state_tx_cnt,
            balance=raw.balance,
            chainId=raw.chain_id,
            solanaAddress=raw.sol_address,
            contractSolanaAddress=raw.contract_sol_address,
        )


class NpAccountApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::Account"

    @NeonProxyApi.method(name="eth_getTransactionCount")
    async def get_tx_cnt(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField,
        block_tag: RpcBlockRequest,
    ) -> HexUIntField:
        block = await self.get_block_by_tag(block_tag)
        chain_id = self._get_chain_id(ctx)
        acct = NeonAccount.from_raw(address, chain_id)

        mp_tx_nonce: int | None = None
        if block.commit == EthCommit.Pending:
            mp_tx_nonce = await self._mp_client.get_pending_tx_cnt(self._get_ctx_id(ctx), acct)
            _LOG.debug("pending tx count for %s is %s", acct, mp_tx_nonce)

        tx_cnt = await self._core_api_client.get_state_tx_cnt(acct, block)
        return max(tx_cnt, mp_tx_nonce or 0)

    @NeonProxyApi.method(name="eth_getBalance")
    async def get_balance(
        self,
        ctx: HttpRequestCtx,
        address: EthNotNoneAddressField,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        chain_id = self._get_chain_id(ctx)
        block = await self.get_block_by_tag(block_tag)
        acct = await self._core_api_client.get_neon_account(NeonAccount.from_raw(address, chain_id), block)

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
        neon_acct = NeonAccount.from_raw(address, chain_id)
        resp = await self._core_api_client.get_neon_contract(neon_acct, block)
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
        address: EthNotNoneAddressField,
        block_tag: RpcBlockRequest,
    ) -> _NeonRpcAccountResp:
        block = await self.get_block_by_tag(block_tag)
        chain_id = self._get_chain_id(ctx)
        acct = NeonAccount.from_raw(address, chain_id)

        resp = await self._core_api_client.get_neon_account(acct, block)
        return _NeonRpcAccountResp.from_raw(resp)

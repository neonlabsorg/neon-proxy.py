from __future__ import annotations

from typing import ClassVar

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthError, EthWrongChainIdError
from common.ethereum.hash import EthAddressField, EthTxHashField
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.jsonrpc.errors import InvalidParamError
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.utils.cached import cached_property
from common.utils.format import hex_to_bytes
from .server_abc import PrivateRpcApi
from ..base.rpc_api import RpcEthTxRequest, RpcEthTxResp
from ..base.rpc_gas_limit_calculator import RpcNeonGasLimitCalculator
from ..base.rpc_transaction_executor import RpcNeonTxExecutor


class _RpcSignEthTxResp(BaseJsonRpcModel):
    tx: RpcEthTxResp
    raw: EthBinStrField


class PrEthTxApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::Transaction"

    @cached_property
    def _gas_calculator(self) -> RpcNeonGasLimitCalculator:
        return RpcNeonGasLimitCalculator(self._server)

    @cached_property
    def _tx_executor(self) -> RpcNeonTxExecutor:
        return RpcNeonTxExecutor(self._server)

    @PrivateRpcApi.method(name="eth_sendTransaction")
    async def eth_send_tx(self, ctx: HttpRequestCtx, tx: RpcEthTxRequest) -> EthTxHashField:
        signed_tx = await self._eth_sign_tx(ctx, tx)
        return await self._tx_executor.send_neon_tx(ctx, signed_tx)

    @PrivateRpcApi.method(name="eth_signTransaction")
    async def eth_sign_tx(self, ctx: HttpRequestCtx, tx: RpcEthTxRequest) -> _RpcSignEthTxResp:
        signed_tx = await self._eth_sign_tx(ctx, tx)
        neon_tx = NeonTxModel.from_raw(signed_tx)
        return _RpcSignEthTxResp(tx=RpcEthTxResp.from_raw(neon_tx), raw=signed_tx)

    @PrivateRpcApi.method(name="eth_sign")
    async def eth_sign(self, ctx: HttpRequestCtx, eth_address: EthAddressField, data: EthBinStrField) -> EthBinStrField:
        data = hex_to_bytes(data)
        msg = str.encode(f"\x19Ethereum Signed Message:\n{len(data)}") + data

        resp = await self._op_client.sign_eth_msg(dict(ctx_id=self._get_ctx_id(ctx)), eth_address, msg)
        if resp.error:
            raise EthError(message=resp.error)

        return resp.signed_msg

    async def _eth_sign_tx(self, ctx: HttpRequestCtx, tx: RpcEthTxRequest) -> bytes:
        chain_id = self._get_chain_id(ctx)
        if tx.chainId and tx.chainId != chain_id:
            raise EthWrongChainIdError()
        elif tx.fromAddress.is_empty:
            raise InvalidParamError(message='no sender in transaction')

        sender_acct = NeonAccount.from_raw(tx.fromAddress, chain_id)
        neon_tx = tx.to_neon_tx()

        if not neon_tx.gas_limit:
            core_tx = tx.to_core_tx(chain_id)
            gas_limit = await self._gas_calculator.estimate(core_tx, dict())
            object.__setattr__(neon_tx, "gas_limit", gas_limit)

        if not neon_tx.nonce:
            nonce = await self._core_api_client.get_state_tx_cnt(sender_acct)
            object.__setattr__(neon_tx, "nonce", nonce)

        ctx_id = self._get_ctx_id(ctx)
        resp = await self._op_client.sign_eth_tx(dict(ctx=ctx_id), neon_tx, chain_id)
        if resp.error:
            raise EthError(message=resp.error)
        return resp.signed_tx.to_bytes()

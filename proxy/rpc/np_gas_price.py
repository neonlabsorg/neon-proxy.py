from __future__ import annotations

from typing import ClassVar

from pydantic import Field, AliasChoices
from typing_extensions import Self

from common.ethereum.errors import EthNonceTooLowError
from common.ethereum.hash import EthAddressField, EthAddress
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import HexUIntField
from .server_abc import NeonProxyApi
from ..base.mp_api import MpTokenGasPriceModel, MpGasPriceModel


class _RpcGasPriceModel(BaseJsonRpcModel):
    tokenName: str
    chainId: HexUIntField

    gasPrice: HexUIntField
    suggestedGasPrice: HexUIntField
    isConstGasPrice: bool
    minAcceptableGasPrice: HexUIntField
    minExecutableGasPrice: HexUIntField

    chainTokenPriceUsd: HexUIntField
    tokenPriceUsd: HexUIntField

    operatorFee: HexUIntField

    solanaCUPriorityFee: HexUIntField
    solanaSimpleCUPriorityFee: HexUIntField


class _RpcDefaultGasPriceModel(_RpcGasPriceModel):
    # defaultPriceUsd: HexUIntField
    minWoChainIDAcceptableGasPrice: HexUIntField

    @classmethod
    def from_raw(
        cls,
        price: MpGasPriceModel,
        token_price: MpTokenGasPriceModel,
        *,
        def_gas_price: int | None = None,
    ) -> Self:
        if def_gas_price is None:
            def_gas_price = token_price.suggested_gas_price

        kwargs = dict(
            tokenName=token_price.token_name,
            chainId=token_price.chain_id,
            gasPrice=def_gas_price,
            suggestedGasPrice=token_price.suggested_gas_price,
            isConstGasPrice=token_price.is_const_gas_price,
            minAcceptableGasPrice=token_price.min_acceptable_gas_price,
            minExecutableGasPrice=token_price.min_executable_gas_price,
            chainTokenPriceUsd=price.chain_token_price_usd,
            tokenPriceUsd=token_price.token_price_usd,
            operatorFee=price.operator_fee,
            solanaCUPriorityFee=price.cu_price,
            solanaSimpleCUPriorityFee=price.simple_cu_price,
        )
        if token_price.is_default_token:
            neon_kwargs = dict(
                minWoChainIDAcceptableGasPrice=price.min_wo_chain_id_acceptable_gas_price,
                # defaultTokenPriceUsd=token_price.token_price_usd,
            )
            return _RpcDefaultGasPriceModel(**kwargs, **neon_kwargs)
        return _RpcGasPriceModel(**kwargs)


class _RpcNativeTokenResp(BaseJsonRpcModel):
    tokenName: str
    tokenMint: SolPubKeyField
    tokenChainID: HexUIntField

    @classmethod
    def from_raw(cls, price: MpTokenGasPriceModel) -> Self:
        return cls(tokenName=price.token_name, tokenMint=price.token_mint, tokenChainID=price.chain_id)


class _RpcGasCallRequest(BaseJsonRpcModel):
    fromAddress: EthAddressField = Field(validation_alias=AliasChoices("from", "fromAddress"))
    toAddress: EthAddressField | None = Field(default=None, validation_alias=AliasChoices("to", "toAddress"))
    nonce: HexUIntField = Field(default=0)
    gas: HexUIntField = Field(default=0)

    _default: ClassVar[_RpcGasCallRequest | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(fromAddress=EthAddress.default(), toAddress=EthAddress.default())
        return cls._default

    def model_post_init(self, _ctx) -> None:
        if not self.fromAddress.is_empty:
            return
        elif (not self.toAddress.is_empty) or self.nonce or self.gas:
            raise ValueError("'to', 'nonce' and 'gas' properties require the 'from'-property")


class NpGasPriceApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::GasPrice"

    @NeonProxyApi.method(name="eth_gasPrice")
    async def get_eth_gas_price(self, ctx: HttpRequestCtx) -> HexUIntField:
        _, token_gas_price = await self.get_token_gas_price(ctx)
        return token_gas_price.suggested_gas_price

    @NeonProxyApi.method(name="neon_gasPrice")
    async def get_neon_gas_price(
        self,
        ctx: HttpRequestCtx,
        call: _RpcGasCallRequest = _RpcGasCallRequest.default(),
    ) -> _RpcGasPriceModel:
        gas_price, token_gas_price = await self.get_token_gas_price(ctx)
        if call.fromAddress.is_empty:
            return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price)

        state_tx_cnt = await self._core_api_client.get_state_tx_cnt(
            NeonAccount.from_raw(call.fromAddress, token_gas_price.chain_id),
            None,
        )
        tx_nonce = call.nonce if call.nonce is not None else state_tx_cnt
        EthNonceTooLowError.raise_if_error(tx_nonce, state_tx_cnt, sender=call.fromAddress)

        tx_gas_limit = call.gas or 0

        if await self.has_fee_less_tx_permit(ctx, call.fromAddress, call.toAddress, tx_nonce, tx_gas_limit):
            return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price, def_gas_price=0)

        return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price)

    @NeonProxyApi.method(name="neon_getNativeTokenList")
    async def get_native_token_list(self) -> list[_RpcNativeTokenResp]:
        gas_price = await self._server.get_gas_price()
        return list(_RpcNativeTokenResp.from_raw(token) for token in gas_price.token_dict.values())

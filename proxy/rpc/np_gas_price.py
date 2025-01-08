from __future__ import annotations

import random
from typing import ClassVar

from pydantic import Field, AliasChoices
from typing_extensions import Final, Self

from common.ethereum.errors import EthError, EthNonceTooLowError
from common.ethereum.hash import EthAddressField, EthAddress
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.address import NeonAddress
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import HexUIntField
from proxy.rpc.api import RpcBlockRequest
from .server_abc import NeonProxyApi
from ..base.mp_api import MpTokenGasPriceModel, MpGasPriceModel

# Maximum number of blocks a User can query in eth_feeHistory.
_FEE_HISTORY_MAX_BLOCK_CNT: Final[int] = 1024


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
    priorityFee: HexUIntField

    solanaCUPriorityFee: HexUIntField
    solanaCUPriorityFeePercentile: HexUIntField
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
            priorityFee=price.priority_fee,
            solanaCUPriorityFee=price.cu_price,
            solanaCUPriorityFeePercentile=price.cu_price_pct,
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
    tokenChainId: HexUIntField

    @classmethod
    def from_raw(cls, price: MpTokenGasPriceModel) -> Self:
        return cls(tokenName=price.token_name, tokenMint=price.token_mint, tokenChainId=price.chain_id)


class _RpcGasCallRequest(BaseJsonRpcModel):
    fromAddress: EthAddressField = Field(validation_alias=AliasChoices("from", "fromAddress"))
    toAddress: EthAddressField = Field(default=None, validation_alias=AliasChoices("to", "toAddress"))
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


class _RpcFeeHistoryResp(BaseJsonRpcModel):
    baseFeePerGas: list[HexUIntField]
    gasUsedRatio: list[float]
    oldestBlock: HexUIntField
    reward: list[list[HexUIntField]] | None

    @classmethod
    def from_raw(
        cls,
        base_fee_list: list[int],
        gas_used_ratio_list: list[float],
        oldest_slot: int,
        reward_list: list[list[int]] | None,
    ) -> Self:
        return cls(
            baseFeePerGas=base_fee_list,
            gasUsedRatio=gas_used_ratio_list,
            oldestBlock=oldest_slot,
            reward=reward_list,
        )

    def model_post_init(self, _ctx) -> None:
        for gasUsedInBlock in self.gasUsedRatio:
            if gasUsedInBlock > 1.0:
                raise ValueError("gas used ratio can't be bigger than 1")
        if (self.reward is not None) and (len(self.baseFeePerGas) != len(self.reward) + 1):
            raise ValueError("baseFeePerGas should contain exactly one element more than reward.")


class NpGasPriceApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::GasPrice"

    @NeonProxyApi.method(name="eth_gasPrice")
    async def get_eth_gas_price(self, ctx: HttpRequestCtx) -> HexUIntField:
        _, token_gas_price = await self._get_token_gas_price(ctx)
        return token_gas_price.suggested_gas_price

    @NeonProxyApi.method(name="neon_gasPrice")
    async def get_neon_gas_price(
        self,
        ctx: HttpRequestCtx,
        call: _RpcGasCallRequest = _RpcGasCallRequest.default(),
    ) -> _RpcGasPriceModel:
        gas_price, token_gas_price = await self._get_token_gas_price(ctx)
        if call.fromAddress.is_empty:
            return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price)

        state_tx_cnt = await self._core_api_client.get_state_tx_cnt(
            NeonAddress.from_raw(call.fromAddress, token_gas_price.chain_id),
            None,
        )
        tx_nonce = call.nonce if call.nonce is not None else state_tx_cnt
        EthNonceTooLowError.raise_if_error(tx_nonce, state_tx_cnt, sender=call.fromAddress)

        tx_gas_limit = call.gas or 0

        if await self._has_fee_less_tx_permit(ctx, call.fromAddress, call.toAddress, tx_nonce, tx_gas_limit):
            return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price, def_gas_price=0)

        return _RpcDefaultGasPriceModel.from_raw(gas_price, token_gas_price)

    @NeonProxyApi.method(name="neon_getNativeTokenList")
    async def get_native_token_list(self) -> list[_RpcNativeTokenResp]:
        gas_price = await self._server.get_gas_price()
        return list(_RpcNativeTokenResp.from_raw(token) for token in gas_price.token_dict.values())

    @NeonProxyApi.method(name="eth_maxPriorityFeePerGas")
    async def get_max_priority_fee_per_gas(self, ctx: HttpRequestCtx) -> HexUIntField:
        _, token_gas_price = await self._get_token_gas_price(ctx)
        return token_gas_price.profitable_gas_price

    @NeonProxyApi.method(name="eth_feeHistory")
    async def get_fee_history(
        self,
        ctx: HttpRequestCtx,
        block_cnt: HexUIntField,
        block_tag: RpcBlockRequest,
        priority_fee_pct_list: list[int] | None,
    ) -> _RpcFeeHistoryResp | None:
        # Treat empty list and None the same.
        has_reward_list: bool = bool(priority_fee_pct_list)

        # Validate input parameters, throw EthError if those are incorrect.
        self._validate_pct_list(priority_fee_pct_list)

        # Fetch the current gas price - it's needed to convert priority_fee prices to gas tokens
        # and to return base_fee_per_gas for the upcoming block.
        _, token_gas_price = await self._get_token_gas_price(ctx)

        # Ethereum clients don't take into account the actual baseFeePerGas
        #   instead they increase this value on some blocks (12.5% per block)
        #   and use it as maxFeePerGas
        suggested_gas_price: int = token_gas_price.suggested_gas_price
        profitable_gas_price: int = token_gas_price.profitable_gas_price

        block_cnt = min(block_cnt, _FEE_HISTORY_MAX_BLOCK_CNT)
        if block_cnt == 0:
            return _RpcFeeHistoryResp.from_raw([suggested_gas_price], [], 0, [])

        block = await self.get_block_by_tag(block_tag)
        latest_slot = block.slot if not block.is_empty else await self._db.get_latest_slot()
        earliest_slot = max(latest_slot - block_cnt + 1, await self._db.get_earliest_slot())

        # Ethereum sets the base_fee_per_gas for the next block, so adding the current gas price.
        base_fee_list: list[int] = [suggested_gas_price for _ in range(earliest_slot, latest_slot + 2)]

        # Filling in the random high number in [0.95, 1] range.
        gas_used_ratio_list: list[float] = [
            (0.95 + random.random() * 0.05)
            for _ in range(earliest_slot, latest_slot + 1)
        ]

        # Filling with percent from priority-fee
        reward_list: list[list[int]] | None = None
        if has_reward_list:
            reward_list: list[list[int]] = [
                [profitable_gas_price for _ in priority_fee_pct_list]
                for _ in range(earliest_slot, latest_slot + 1)
            ]

        return _RpcFeeHistoryResp.from_raw(base_fee_list, gas_used_ratio_list, earliest_slot, reward_list)

    @staticmethod
    def _validate_pct_list(pct_list: list[int] | None):
        if not pct_list:
            return
        prev_p = -1
        for p in pct_list:
            if p < 0 or p > 100:
                raise EthError(message="Invalid priority fee percentiles: should be in [0, 100] range.")
            elif prev_p >= p:
                raise EthError(message="Invalid priority fee percentiles: should be an increasing sequence.")
            prev_p = p

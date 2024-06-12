from __future__ import annotations

from bisect import bisect_left
import math
from typing import ClassVar

from indexer.db.neon_tx_db import BlockFeeGasData
from proxy.rpc.api import RpcBlockRequest
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


# Hardcoded priority fee percentiles that are supported by eth_feeHistory.
_REWARD_PERCENTILES: list[int] = [i * 10 for i in range(11)]


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
    reward: list[list[HexUIntField]]

    @classmethod
    def from_raw(
        cls, base_fee: list[int], gas_used_ratio: list[float], oldest_block: int, reward: list[list[int]]
    ) -> Self:
        return cls(baseFeePerGas=base_fee, gasUsedRatio=gas_used_ratio, oldestBlock=oldest_block, reward=reward)

    def model_post_init(self, _ctx) -> None:
        for gasUsedInBlock in self.gasUsedRatio:
            if gasUsedInBlock > 1.0:
                raise ValueError("gas used ratio can't be bigger than 1")
        if len(self.baseFeePerGas) != len(self.reward) + 1:
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
            NeonAccount.from_raw(call.fromAddress, token_gas_price.chain_id),
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
        # Fetch the compute units price across last several blocks (as specified in the cfg).
        num_blocks = self._cfg.priority_fee_num_blocks_to_average
        assert num_blocks > 0
        historical_priority_fees: list[list[int]] = await self._db.get_historical_priority_fees(num_blocks)
        assert num_blocks == len(historical_priority_fees)

        # Take the weighted average across fetched blocks.
        average_weighted_max_priority_fee = 0
        for idx, block_priority_fees in enumerate(historical_priority_fees):
            # Sanity check to avoid division by zero.
            average_block_priority_fee = 0
            if len(block_priority_fees) != 0:
                average_block_priority_fee = sum(block_priority_fees) / len(block_priority_fees)
            # The most recent block goes with the biggest weight.
            average_weighted_max_priority_fee += average_block_priority_fee * (num_blocks - idx)
        average_block_priority_fee /= num_blocks * (num_blocks + 1) / 2

        # Convert it into ethereum world by multiplying by suggested_gas_price
        # N.B. prices in the block are stored in microlamports, so conversion to lamports takes place.
        _, token_gas_price = await self.get_token_gas_price(ctx)
        return int(token_gas_price.suggested_gas_price * average_block_priority_fee / 1_000_000)

    @NeonProxyApi.method(name="eth_feeHistory")
    async def get_fee_history(
        self,
        ctx: HttpRequestCtx,
        num_blocks: HexUIntField,
        block_tag: RpcBlockRequest,
        priority_fee_percentiles: list[int] | None,
    ) -> _RpcFeeHistoryResp | None:
        if not priority_fee_percentiles:
            # In case the User was lazy to request any percentiles, let's return "median"
            # so the response makes sense.
            priority_fee_percentiles = [50]
        # Validate percentiles first before querying anything.
        for p in priority_fee_percentiles:
            if p < 0 or p > 100:
                return None

        # Fetch the latest block slot.
        block = await self.get_block_by_tag(block_tag)
        # Max value for the bigint type.
        # In case block is latest and it's empty, let's use this max value
        # instead of making an extra get_latest_block DB query.
        latest_slot = 9223372036854775807
        if not block.is_empty:
            latest_slot = block.slot

        # Let's clamp num_blocks to not create excessive load and attack vector from RPC clients.
        # Infura and Alchemy currently do the same.
        num_blocks = max(1, min(num_blocks, 1024))
        # Fetching the data stage.
        fee_gas_data: list[BlockFeeGasData] = await self._db.get_historical_base_fees(
            self.get_chain_id(ctx), num_blocks, latest_slot
        )
        priority_fees_data: list[list[int]] = await self._db.get_historical_priority_fees(num_blocks)

        # Since we are effectively querying different tables, let's reconcile length of the data,
        # so we return consistent data (in case one array is bigger than the other).
        num_blocks = min(len(fee_gas_data), len(priority_fees_data))
        if num_blocks == 0:
            # For some reason, the number of "blocks" we have is zero, so return the current base fee price.
            _, token_gas_price = await self.get_token_gas_price(ctx)
            current_gas_price: int = token_gas_price.suggested_gas_price
            return _RpcFeeHistoryResp.from_raw([current_gas_price], [], 0, [])

        fee_gas_data = fee_gas_data[-num_blocks:]
        priority_fees_data = priority_fees_data[-num_blocks:]

        # Processing stage. Data entries are sorted in descending order by slot.
        # BaseFees:
        base_fees: list[int] = [
            math.ceil(fee_gas_data[idx].average_base_fee) for idx in range(len(fee_gas_data) - 1, -1, -1)
        ]
        # Since ethereum deterministically derives the next base_fee_per_gas for the upcoming block,
        # we have to do the same - return the current gas price (the same as in the eth_gasPrice).
        _, token_gas_price = await self.get_token_gas_price(ctx)
        current_gas_price: int = token_gas_price.suggested_gas_price
        base_fees.append(current_gas_price)

        # GasUsedRatio:
        gas_used_ratio = [
            min(1.0, fee_gas_data[idx].total_gas_used / 48_000_000_000_000)
            for idx in range(len(fee_gas_data) - 1, -1, -1)
        ]

        # OldestBlock:
        oldest_block = fee_gas_data[-1].slot if len(fee_gas_data) > 0 else 0

        # Reward:
        # Because we store only 10th percentiles for priority fees, let's linearly extrapolate for other data points.
        def _calc_single_priority_fee_extrapolated(percentile: int, values: list[int]) -> float:
            assert len(values) == len(_REWARD_PERCENTILES)
            biggest_known_p_idx = bisect_left(_REWARD_PERCENTILES, percentile)
            if _REWARD_PERCENTILES[biggest_known_p_idx] == percentile:
                return values[biggest_known_p_idx]
            start_val = values[biggest_known_p_idx - 1]
            end_val = values[biggest_known_p_idx]
            # 10 is a gap between consequtive percentiles.
            return start_val + (end_val - start_val) * (percentile - _REWARD_PERCENTILES[biggest_known_p_idx - 1]) / 10

        # Calculate priority fee in gas tokens according to input percentiles.
        def _calc_priority_fee_list(percentiles: list[int], values: list[int]) -> list[int]:
            # Because we extrapolate from compute unit prices denominated in microlamports,
            # conversion to lamports and into the gas token should apply.
            return [
                math.ceil(_calc_single_priority_fee_extrapolated(p, values) * current_gas_price / 1_000_000)
                for p in percentiles
            ]

        rewards: list[list[int]] = [
            _calc_priority_fee_list(priority_fee_percentiles, priority_fees_data[idx])
            for idx in range(len(priority_fees_data) - 1, -1, -1)
        ]

        return _RpcFeeHistoryResp.from_raw(base_fees, gas_used_ratio, oldest_block, rewards)

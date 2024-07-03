from __future__ import annotations

from bisect import bisect_left
import math
from typing import ClassVar


from indexer.db.neon_tx_db import BlockFeeGasData
from indexer.db.solana_block_db import PriorityFeePercentiles
from proxy.rpc.api import RpcBlockRequest
from pydantic import Field, AliasChoices
from typing_extensions import Self

from common.ethereum.errors import EthError, EthNonceTooLowError
from common.ethereum.hash import EthAddressField, EthAddress
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.neon.block import NeonBlockHdrModel
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import HexUIntField
from .server_abc import NeonProxyApi
from ..base.mp_api import MpTokenGasPriceModel, MpGasPriceModel


# Hardcoded priority fee percentiles that are supported by eth_feeHistory.
_REWARD_PERCENTILE_LIST: list[int] = [
    i * NeonBlockHdrModel.PercentileStep for i in range(NeonBlockHdrModel.PercentileCount)
]
# Max value for the block_slot (which is of a bigint type in the Postgres).
_MAX_LATEST_BLOCK: int = 9223372036854775807


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
        block_cnt = self._cfg.priority_fee_block_cnt_to_avg
        assert block_cnt > 0
        historical_cu_price_list: list[PriorityFeePercentiles] = await self._db.get_historical_priority_fees(
            block_cnt, _MAX_LATEST_BLOCK
        )

        # Take the weighted average across fetched blocks.
        average_weighted_max_priority_fee = 0
        for idx, block_cu_price_list in enumerate(historical_cu_price_list):
            cu_price_list: list[int] = block_cu_price_list.cu_price_percentiles
            avg_block_cu_price = 0
            # Sanity check to avoid division by zero.
            if cu_price_list:
                avg_block_cu_price = sum(cu_price_list) / len(cu_price_list)
            # The most recent block goes with the biggest weight.
            average_weighted_max_priority_fee += avg_block_cu_price * (block_cnt - idx)
        avg_block_cu_price /= block_cnt * (block_cnt + 1) / 2

        # Convert it into ethereum world by multiplying by suggested_gas_price
        # N.B. prices in the block are stored in microlamports, so conversion to lamports takes place.
        _, token_gas_price = await self._get_token_gas_price(ctx)
        return int(token_gas_price.suggested_gas_price * avg_block_cu_price / 1_000_000)

    @NeonProxyApi.method(name="eth_feeHistory")
    async def get_fee_history(
        self,
        ctx: HttpRequestCtx,
        block_cnt: HexUIntField,
        block_tag: RpcBlockRequest,
        priority_fee_percentile_list: list[int] | None,
    ) -> _RpcFeeHistoryResp | None:
        if not priority_fee_percentile_list:
            # In case the User was lazy to request any percentiles, let's return "median"
            # so the response makes sense.
            priority_fee_percentile_list = [50]

        # Validate input parameters, throw EthError if those are incorrect.
        self._validate_fee_history_inputs(block_cnt, priority_fee_percentile_list)

        # Fetch the current gas price - it's needed to convert price to gas tokens
        # and to return base_fee_per_gas for the upcoming block.
        _, token_gas_price = await self._get_token_gas_price(ctx)
        current_gas_price: int = token_gas_price.suggested_gas_price

        # Fetch the latest block slot.
        block = await self.get_block_by_tag(block_tag)
        # In case block is latest and it's empty, let's use this max value
        # instead of making an extra get_latest_block DB query.
        latest_slot = _MAX_LATEST_BLOCK
        if not block.is_empty:
            latest_slot = block.slot

        # Let's clamp num_blocks to not create excessive load - Infura and Alchemy currently do the same.
        block_cnt = min(block_cnt, 1024)
        # Fetching the data stage.
        fee_gas_data_list: list[BlockFeeGasData] = await self._db.get_historical_base_fees(
            self._get_chain_id(ctx), block_cnt, latest_slot
        )
        cu_price_data_list: list[PriorityFeePercentiles] = await self._db.get_historical_priority_fees(
            block_cnt, latest_slot
        )

        # Response objects.
        base_fee_list: list[int] = []
        gas_used_ratio_list: list[float] = []
        reward_list: list[list[int]] = []

        # Iterate through the fee_gas_data_list and cu_price_data_list using two pointers.
        # Both lists are sorted in the descending by block_slot order.
        # Also, fee_gas_data_list may miss entries for some blocks. In such a case, let's fill the output
        # with the previous base_fee_per_gas we encounter (or with 0 until we see the first one).
        fee_data_it: int = len(fee_gas_data_list) - 1
        cu_data_it: int = len(cu_price_data_list) - 1
        last_base_fee_per_gas: int = 0
        while cu_data_it >= 0:
            # Skip data about base_fee that is older than the current block slot we consider.
            while (
                fee_data_it >= 0
                and cu_price_data_list[cu_data_it].block_slot > fee_gas_data_list[fee_data_it].block_slot
            ):
                fee_data_it -= 1

            if (
                fee_data_it >= 0
                and cu_price_data_list[cu_data_it].block_slot == fee_gas_data_list[fee_data_it].block_slot
            ):
                cur_base_fee = math.ceil(fee_gas_data_list[fee_data_it].average_base_fee)
                # The current gas_fee_data_list entry belongs to the current block.
                # Fill in the output data, remember the last_base_fee_per_gas and move the iterator.
                base_fee_list.append(cur_base_fee)
                gas_used_ratio_list.append(min(1.0, fee_gas_data_list[fee_data_it].total_gas_used / 48_000_000_000_000))
                last_base_fee_per_gas = cur_base_fee
                fee_data_it -= 1
            else:
                base_fee_list.append(last_base_fee_per_gas)
                gas_used_ratio_list.append(0.0)

            reward_list.append(
                self._calc_priority_fee_list(
                    priority_fee_percentile_list, cu_price_data_list[cu_data_it].cu_price_percentiles, current_gas_price
                )
            )
            cu_data_it -= 1

        # Since ethereum deterministically derives the next base_fee_per_gas for the upcoming block,
        # we have to do the same - return the current gas price (the same as in the eth_gasPrice).
        base_fee_list.append(current_gas_price)
        oldest_block: int = cu_price_data_list[-1].block_slot if cu_price_data_list else 0
        return _RpcFeeHistoryResp.from_raw(base_fee_list, gas_used_ratio_list, oldest_block, reward_list)

    def _validate_fee_history_inputs(
        self,
        block_cnt: HexUIntField,
        priority_fee_percentile_list: list[int],
    ):
        if block_cnt == 0:
            raise EthError("Block count should be positive.")
        for p in priority_fee_percentile_list:
            if p < 0 or p > 100:
                raise EthError(message="Invalid priority fee percentiles: should be in [0, 100] range.")
        for i in range(len(priority_fee_percentile_list) - 1):
            if priority_fee_percentile_list[i] >= priority_fee_percentile_list[i + 1]:
                raise EthError(message="Invalid priority fee percentiles: should be an increasing sequence.")

    def _calc_single_priority_fee_extrapolated(
        self, percentile: int, priority_fee_percentiles_list: list[int]
    ) -> float:
        """
        Calculate a `percentile` of priority fee given a list of known percentiles for priority fee prices.
        Because we only store values at fixed percentiles, a linear extrapolation is used in case
        the desired `percentile` is missing.
        """
        assert len(priority_fee_percentiles_list) == len(_REWARD_PERCENTILE_LIST)
        biggest_known_p_idx = bisect_left(_REWARD_PERCENTILE_LIST, percentile)
        if _REWARD_PERCENTILE_LIST[biggest_known_p_idx] == percentile:
            return priority_fee_percentiles_list[biggest_known_p_idx]
        start_val = priority_fee_percentiles_list[biggest_known_p_idx - 1]
        end_val = priority_fee_percentiles_list[biggest_known_p_idx]
        return (
            start_val
            + (end_val - start_val)
            * (percentile - _REWARD_PERCENTILE_LIST[biggest_known_p_idx - 1])
            / NeonBlockHdrModel.PercentileStep
        )

    def _calc_priority_fee_list(
        self, percentiles: list[int], priority_fee_percentiles_list: list[int], cur_gas_price: int
    ) -> list[int]:
        """
        Calculate the list of `percentiles` of priority fee rewards.
        The values are scaled by `cur_gas_price`, so the rewards are denominated in the gas tokens.
        """
        # Because we extrapolate from compute unit prices denominated in microlamports,
        # conversion to lamports and into the gas token should apply.
        return [
            math.ceil(
                self._calc_single_priority_fee_extrapolated(p, priority_fee_percentiles_list)
                * cur_gas_price
                / 1_000_000
            )
            for p in percentiles
        ]

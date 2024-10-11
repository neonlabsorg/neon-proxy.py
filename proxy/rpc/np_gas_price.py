from __future__ import annotations

import math
import random
from typing import ClassVar

from pydantic import Field, AliasChoices
from typing_extensions import Final, Self

from common.ethereum.errors import EthError, EthNonceTooLowError
from common.ethereum.hash import EthAddressField, EthAddress
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.account import NeonAccount
from common.neon.block import NeonBlockCuPriceInfo, NeonBlockBaseFeeInfo
from common.neon.cu_price_data_model import CuPricePercentileModel
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import HexUIntField
from proxy.rpc.api import RpcBlockRequest
from .server_abc import NeonProxyApi
from ..base.mp_api import MpSlotGasPriceModel, MpTokenGasPriceModel, MpGasPriceModel

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
        pp = self._cfg.cu_price_estimator_percentile
        block_cnt = self._cfg.cu_price_estimator_block_cnt

        block_list = await self._db.get_block_cu_price_list(block_cnt)

        median_cu_price: float = CuPricePercentileModel.get_weighted_percentile(
            pp, len(block_list), map(lambda v: v.cu_price_list, block_list)
        )

        # Convert it into ethereum world by multiplying by suggested_gas_price
        # N.B. prices in the block are stored in microlamports, so conversion to lamports takes place.
        _, token_gas_price = await self._get_token_gas_price(ctx)
        return int(token_gas_price.suggested_gas_price * median_cu_price / 1_000_000)

    @NeonProxyApi.method(name="eth_feeHistory")
    async def get_fee_history(
        self,
        ctx: HttpRequestCtx,
        block_cnt: HexUIntField,
        block_tag: RpcBlockRequest,
        priority_fee_percentile_list: list[int] | None,
    ) -> _RpcFeeHistoryResp | None:
        # Treat empty list and None the same.
        is_reward_list: bool = bool(priority_fee_percentile_list)

        # Validate input parameters, throw EthError if those are incorrect.
        self._validate_percentile_list(priority_fee_percentile_list)

        # Fetch the current gas price - it's needed to convert priority_fee prices to gas tokens
        # and to return base_fee_per_gas for the upcoming block.
        _, token_gas_price = await self._get_token_gas_price(ctx)
        current_gas_price: int = token_gas_price.suggested_gas_price

        if block_cnt == 0:
            return _RpcFeeHistoryResp.from_raw([current_gas_price], [], 0, [])

        block = await self.get_block_by_tag(block_tag)
        if not block.is_empty:
            latest_slot = block.slot
        else:
            # Fetch the latest block slot.
            latest_slot = await self._db.get_latest_slot()

        # Let's clamp number of blocks to not create excessive load - Infura and Alchemy currently do the same.
        block_cnt = min(block_cnt, _FEE_HISTORY_MAX_BLOCK_CNT)

        # Fetching the data about compute units on Solana.
        block_cu_price_list: tuple[NeonBlockCuPriceInfo, ...] = tuple()
        if is_reward_list:
            block_cu_price_list: tuple[NeonBlockCuPriceInfo, ...] = await self._db.get_block_cu_price_list(
                block_cnt, latest_slot
            )

        # Determine the earliest_block in the response.
        # If cu_price_data_list is requested and available, take as the earliest block slot.
        # Otherwise, take `block_cnt` blocks backwards starting from what's requested.
        # Also, let's clamp it against the earliest neon block so the response makes sense.
        earliest_slot: int = block_cu_price_list[-1].slot if block_cu_price_list else latest_slot - block_cnt + 1
        earliest_slot = max(earliest_slot, await self._db.get_earliest_slot())

        # Fetching the data about base fees on Neon.
        # The source of base_fee_per_gas data is either from the mempool (for the most recent blocks),
        # or from the DB (for historical blocks).
        # The reason for that is twofold:
        # 1. Sparse non-empty Neon blocks. In case the User requested recent data, an operator returns recent
        #   prices for the gas token regardless of what was set in Neon transactions.
        # 2. Different incentives for different operators. Some operators may set the operator profit margin lower,
        #   so the only way for them to benefit from that is if we return recent suggested token gas price from
        #   their mempool and not from the transactions.
        # However, the recent pricing (from the mempool) is timestamp-based while DB data is block_slot-based,
        # so we need to do some heuristic conversion.
        # The assumption we take here for pricing from the mempool: it corresponds to the most recent block_slot,
        # even though it's not strictly accurate all the time (requests to Pyth may return errors sometimes).
        block_base_fee_list: list[NeonBlockBaseFeeInfo] = list()
        # First, take the token gas price data from the mempool (without querying the DB).
        mp_base_fee_list: list[MpSlotGasPriceModel] = token_gas_price.gas_price_list
        if mp_base_fee_list:
            # Construct entries into base_fee_data_list from in-memory mempool-based recent token gas prices.
            for base_fee in reversed(mp_base_fee_list):
                block_base_fee_list.append(
                    NeonBlockBaseFeeInfo(slot=base_fee.slot, base_fee=base_fee.gas_price)
                )
                if base_fee.slot <= earliest_slot:
                    # We filled in enough data, no need to proceed.
                    break

        # Check if base_fee_data_list has enough data to cover the requested block range,
        # if not enough, fetch base_fee_per_gas from Neon Transactions DB table and fill up the rest.
        if (not block_base_fee_list) or (block_base_fee_list[-1].slot > earliest_slot):
            query_slot: int = latest_slot if not block_base_fee_list else block_base_fee_list[-1].slot - 1
            db_base_fee_list: tuple[NeonBlockBaseFeeInfo, ...] = await self._db.get_block_base_fee_list(
                self._get_chain_id(ctx), block_cnt, query_slot
            )
            block_base_fee_list.extend(db_base_fee_list)

        # Response data objects.
        base_fee_list: list[int] = []
        gas_used_ratio_list: list[float] = []
        reward_list: list[list[int]] = []

        # In case reward list is absent or cu_price_data_list has no data - fill base fee data and return.
        if not block_cu_price_list:
            fee_data_it: int = len(block_base_fee_list) - 1
            # Set last base_fee we know to be the current gas price as initial value.
            last_base_fee: int = current_gas_price
            for slot in range(earliest_slot, latest_slot + 1):
                while fee_data_it >= 0 and slot >= block_base_fee_list[fee_data_it].slot:
                    last_base_fee = block_base_fee_list[fee_data_it].base_fee
                    fee_data_it -= 1
                base_fee_list.append(last_base_fee)
                gas_used_ratio_list.append(self._get_gas_used_ratio())
            # Ethereum sets the base_fee_per_gas for the next block, so adding the current gas price.
            base_fee_list.append(current_gas_price)
            return _RpcFeeHistoryResp.from_raw(base_fee_list, gas_used_ratio_list, earliest_slot, None)

        # Iterate through the fee_gas_data_list and cu_price_data_list using two pointers.
        # Both lists are sorted in the descending by block_slot order.
        # fee_gas_data_list does not have data for some slots - we fill the response
        # with the previous base_fee_per_gas we encountered.
        fee_data_it: int = len(block_base_fee_list) - 1
        cu_data_it: int = len(block_cu_price_list) - 1
        # Set last base_fee we know to be the current gas price as initial value.
        last_base_fee: int = current_gas_price
        while cu_data_it >= 0 and block_cu_price_list[cu_data_it].slot >= earliest_slot:
            # Skip data about base_fee that is older than the current block slot we consider.
            # Memorize the last_base_fee_per_gas and move the iterator.
            while fee_data_it >= 0 and block_cu_price_list[cu_data_it].slot >= block_base_fee_list[fee_data_it].slot:
                last_base_fee = block_base_fee_list[fee_data_it].base_fee
                fee_data_it -= 1

            base_fee_list.append(last_base_fee)
            reward_list.append(
                self._calc_priority_fee_list(
                    priority_fee_percentile_list,
                    block_cu_price_list[cu_data_it].cu_price_list,
                    current_gas_price,
                )
            )
            gas_used_ratio_list.append(self._get_gas_used_ratio())
            cu_data_it -= 1

        # Ethereum sets the base_fee_per_gas for the next block, so adding the current gas price.
        base_fee_list.append(current_gas_price)
        return _RpcFeeHistoryResp.from_raw(base_fee_list, gas_used_ratio_list, earliest_slot, reward_list)

    @staticmethod
    def _validate_percentile_list(percentile_list: list[int] | None):
        if not percentile_list:
            return
        prev_p = -1
        for p in percentile_list:
            if p < 0 or p > 100:
                raise EthError(message="Invalid priority fee percentiles: should be in [0, 100] range.")
            elif prev_p >= p:
                raise EthError(message="Invalid priority fee percentiles: should be an increasing sequence.")
            prev_p = p

    @staticmethod
    def _get_gas_used_ratio() -> float:
        # Filling in the random high number in [0.85, 1] range.
        return 0.85 + random.random() * 0.15

    @staticmethod
    def _calc_priority_fee_list(
        percentile_list: list[int], priority_fee_percentile_list: list[int], current_gas_price: int
    ) -> list[int]:
        """
        Calculate the list of `percentiles` of priority fee rewards.
        The values are scaled by `cur_gas_price`, so the rewards are denominated in the gas tokens.
        """
        # Because we extrapolate from compute unit prices denominated in microlamports,
        # conversion to lamports and into the gas token should apply.
        return [
            math.ceil(
                CuPricePercentileModel.from_raw(priority_fee_percentile_list).get_percentile(p)
                * current_gas_price
                / 1_000_000
            )
            for p in percentile_list
        ]

from __future__ import annotations

from bisect import bisect_left
import math
from typing import Any, ClassVar, Final, Iterable
from typing_extensions import Self

from ..solana.sys_program import SolSysProg

from ..solana.transaction_decoder import SolTxMetaInfo

from ..solana.block import SolRpcBlockInfo
from ..utils.pydantic import BaseModel


class CuPricePercentilesModel(BaseModel):
    _PercentileStep: Final[int] = 10  # Percentiles are a multiple of 10.
    _PercentileCount: Final[int] = 11  # 100 / step + 1.
    _PercentileList: Final[list[int]] = [i * 10 for i in range(11)]  # 0, 10, ..., 100

    _default: ClassVar[list[int] | None] = None

    data: list[int] = list()

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(data=[0] * cls._PercentileCount)
        return cls._default

    def model_post_init(self, _ctx: Any) -> None:
        if len(self.data) != self._PercentileCount:
            raise ValueError(f"Compute Units Percentiles should contain exactly {self._PercentileCount} elements")

    @classmethod
    def from_raw(cls, cu_prices_data: list[int]) -> Self:
        return cls(data=cu_prices_data)

    @classmethod
    def from_sol_block(cls, sol_block: SolRpcBlockInfo) -> Self:
        # Build a full list of compute unit prices in the solana block.
        price_list: list[int] = list()
        for sol_tx in sol_block.tx_list:
            sol_tx_meta = SolTxMetaInfo.from_raw(sol_block.slot, sol_tx)
            # Filter out transactions to Vote program from the block, as they spoil cu_price stats.
            if SolSysProg.VoteProgram not in sol_tx_meta.account_key_list:
                price_list.append(sol_tx_meta.sol_tx_cu.cu_price)

        if not price_list:
            return cls.default()
        price_list.sort()
        # Take every i * PercentileStep percentile in a sorted list.
        return cls.from_raw(
            [
                price_list[math.floor((len(price_list) - 1) * p * cls._PercentileStep / 100)]
                for p in range(cls._PercentileCount)
            ]
        )

    def get_percentile(self, pp: int) -> float:
        """
        Calculate a `pp` percentile of priority fee from stored cu prices.
        Because we only store values at fixed percentiles, a linear extrapolation is used in case
        the desired `pp` is missing.
        """
        biggest_known_p_idx = bisect_left(self._PercentileList, pp)
        if self._PercentileList[biggest_known_p_idx] == pp:
            return self.data[biggest_known_p_idx]
        start_val = self.data[biggest_known_p_idx - 1]
        end_val = self.data[biggest_known_p_idx]
        return (
            start_val
            + (end_val - start_val) * (pp - self._PercentileList[biggest_known_p_idx - 1]) / self._PercentileStep
        )

    def get_median(self) -> float:
        return self.get_percentile(50)

    @classmethod
    def get_weighted_percentile(cls, pp: int, num_data_points: int, price_seq: Iterable[list[int]]) -> float:
        """
        Returns weighted average of `pp` percentiles for each price data in `price_seq`.
        The first price data is taked with the most significant weight.
        """
        val: float = 0
        for idx, price_data in enumerate(price_seq):
            # Skip data for empty blocks, treat it as 0.
            if not price_data:
                continue
            val += CuPricePercentilesModel.from_raw(price_data).get_percentile(pp) * (num_data_points - idx)
        return val / (num_data_points * (num_data_points + 1) / 2)

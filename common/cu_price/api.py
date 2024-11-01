import dataclasses
from decimal import Decimal
from typing import Sequence

from ..config.config import CuPriceLevel, CuPriceMode
from ..solana.pubkey import SolPubKey


@dataclasses.dataclass(frozen=True)
class PriorityFeeCfg:
    operator_fee: Decimal

    const_gas_price: int | None
    min_gas_price: int | None

    cu_price_mode: CuPriceMode
    cu_price_level: CuPriceLevel
    def_cu_price: int
    def_simple_cu_price: int


@dataclasses.dataclass(frozen=True)
class CuPriceRequest:
    cu_price_mode: CuPriceMode
    cu_price_level: CuPriceLevel
    def_cu_price: int
    account_key_list: Sequence[SolPubKey]

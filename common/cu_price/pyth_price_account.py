from __future__ import annotations

from typing import Final

from typing_extensions import Self

from ..solana.account import SolAccountModel
from ..solana.pubkey import SolPubKey
from ..utils.cached import reset_cached_method


class PythPriceAccount:
    _price_offset: Final[int] = 73
    _price_len: Final[int] = 8
    _exp_offset: Final[int] = 89
    _exp_len: Final[int] = 4
    _end_pos: Final[int] = max(_price_offset + _price_len, _exp_offset + _exp_len)

    def __init__(self, token: str, address: SolPubKey) -> None:
        self._token = token
        self._address = address
        self._data = bytes()

    @classmethod
    def default(cls) -> PythPriceAccount:
        return PythPriceAccount("UNKNOWN", SolPubKey.default())

    @classmethod
    def new_empty(cls, token: str, address: SolPubKey) -> Self:
        return PythPriceAccount(token, address)

    def update_data(self, data: SolAccountModel | bytes | None) -> None:
        self._data = data.data if isinstance(data, SolAccountModel) else data
        self._get_price.reset_cache(self)

    @property
    def address(self) -> SolPubKey:
        return self._address

    @property
    def token(self) -> str:
        return self._token

    @property
    def price(self) -> float:
        return self._get_price()

    @property
    def is_empty(self) -> bool:
        return not len(self._data)

    @reset_cached_method
    def _get_price(self) -> float:
        if (not self._data) or (len(self._data) < self._end_pos):
            return 0.0

        raw_price = self._data[self._price_offset:self._price_offset + self._price_len]
        price = int.from_bytes(raw_price, byteorder='little', signed=False)
        raw_exp = self._data[self._exp_offset:self._exp_offset + self._exp_len]
        exp = int.from_bytes(raw_exp, byteorder='little', signed=True)

        return price * (10 ** exp)

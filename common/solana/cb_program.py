from enum import IntEnum
from typing import Final

import solders.compute_budget as _cb

from .instruction import SolTxIx
from .pubkey import SolPubKey


class SolCuIxCode(IntEnum):
    HeapSize = 1
    CuLimit = 2
    CuPrice = 3


class SolCbProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_cb.ID)

    @classmethod
    def make_heap_size_ix(cls, size: int = 0) -> SolTxIx:
        return _cb.request_heap_frame(size or 256 * 1024)

    @classmethod
    def make_cu_limit_ix(cls, unit_cnt: int = 0) -> SolTxIx:
        return _cb.set_compute_unit_limit(unit_cnt or 1_400_000)

    @classmethod
    def make_cu_price_ix(cls, micro_lamport_cnt: int) -> SolTxIx:
        return _cb.set_compute_unit_price(micro_lamport_cnt)

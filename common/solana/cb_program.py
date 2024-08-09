from enum import IntEnum
from typing import Final

import solders.compute_budget as _cb

from ..config.constants import SOLANA_DEFAULT_CU_LIMIT, SOLANA_MAX_CU_LIMIT, SOLANA_MAX_HEAP_SIZE

from .instruction import SolTxIx
from .pubkey import SolPubKey


class SolCuIxCode(IntEnum):
    HeapSize = 1
    CuLimit = 2
    CuPrice = 3


class SolCbProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_cb.ID)
    MaxCuLimit: Final[int] = SOLANA_MAX_CU_LIMIT
    DefCuLimit: Final[int] = SOLANA_DEFAULT_CU_LIMIT
    MaxHeapSize: Final[int] = SOLANA_MAX_HEAP_SIZE
    BaseCuPrice: Final[int] = 10_000

    @classmethod
    def make_heap_size_ix(cls, size: int) -> SolTxIx:
        return _cb.request_heap_frame(size)

    @classmethod
    def make_cu_limit_ix(cls, unit_cnt: int) -> SolTxIx:
        return _cb.set_compute_unit_limit(unit_cnt)

    @classmethod
    def make_cu_price_ix(cls, micro_lamport_cnt: int) -> SolTxIx:
        return _cb.set_compute_unit_price(micro_lamport_cnt)

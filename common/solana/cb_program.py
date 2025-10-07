from __future__ import annotations

import dataclasses
from enum import IntEnum
from typing import Final, Self, ClassVar, Sequence

import solders.compute_budget as _cb

from .instruction import SolTxIx
from .pubkey import SolPubKey
from .transaction_legacy import SolLegacyTx
from ..config.constants import SOLANA_DEF_HEAP_SIZE, SOLANA_MAX_HEAP_SIZE, SOLANA_DEF_CU_LIMIT, SOLANA_MAX_CU_LIMIT
from ..utils.cached import cached_property


class SolCbIxCode(IntEnum):
    HeapSize = 1
    CuLimit = 2
    CuPrice = 3


class SolCbProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_cb.ID)
    # CUs limit
    MaxCuLimit: Final[int] = SOLANA_MAX_CU_LIMIT
    DefCuLimit: Final[int] = SOLANA_DEF_CU_LIMIT
    # HEAP size
    DefHeapSize: Final[int] = SOLANA_DEF_HEAP_SIZE
    MaxHeapSize: Final[int] = SOLANA_MAX_HEAP_SIZE
    # Base unit
    MicroLamport: Final[int] = pow(10, 6)
    # CU prices less than 10_000 don't work
    BaseCuPrice: Final[int] = 10_500
    MaxPriorityFee: Final[int] = 100 * pow(10, 9)  # 100!? SOLs

    @classmethod
    def make_heap_size_ix(cls, size: int) -> SolTxIx:
        return _cb.request_heap_frame(size)

    @classmethod
    def make_cu_limit_ix(cls, unit_cnt: int) -> SolTxIx:
        return _cb.set_compute_unit_limit(unit_cnt)

    @classmethod
    def make_cu_price_ix(cls, micro_lamport_cnt: int) -> SolTxIx:
        return _cb.set_compute_unit_price(micro_lamport_cnt)

    @classmethod
    def make_legacy_tx(cls, cfg: SolCbCfg, ix_list: SolTxIx | Sequence[SolTxIx]) -> SolLegacyTx:
        res_ix_list: list[SolTxIx] = list()

        if isinstance(ix_list, SolTxIx):
            ix_list = tuple([ix_list])

        tx_name = "+".join(set(map(lambda x: x.name, ix_list)))

        if cfg.cu_price >= 0:
            res_ix_list.append(cls.make_cu_price_ix(cfg.cu_price))
        if cfg.cu_limit not in (0, cls.DefCuLimit):
            res_ix_list.append(cls.make_cu_limit_ix(cfg.cu_limit))
        if cfg.heap_size > cls.DefHeapSize:
            res_ix_list.append(cls.make_heap_size_ix(cfg.heap_size))

        res_ix_list.extend(ix_list)
        return SolLegacyTx(name=tx_name, ix_list=res_ix_list)


@dataclasses.dataclass(frozen=True)
class SolCbCfg:
    # Compute Unit limit
    cu_limit: int = 0
    max_cu_limit: int = SolCbProg.MaxCuLimit
    round_cu_coeff: int = 1_000
    inc_cu_coeff: int = 3_000
    # Compute Unit Price
    cu_price: int = 0  # micro lamports
    max_priority_fee: int = 0  # lamports
    # Heap Frame Size
    heap_size: int = SolCbProg.DefHeapSize

    _Default: ClassVar[SolCbCfg | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._Default:
            cls._Default = cls()
        return cls._Default

    @cached_property
    def threshold_cu_limit(self) -> int:
        return self.max_cu_limit - self.inc_cu_coeff

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def clone(self, **kwargs) -> Self:
        return dataclasses.replace(self, **kwargs)

    def round_cu(self, cu_consumed: int) -> int:
        return min((cu_consumed // self.round_cu_coeff) * self.round_cu_coeff + self.inc_cu_coeff, self.max_cu_limit)

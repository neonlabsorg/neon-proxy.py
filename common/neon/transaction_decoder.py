from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterator

from typing_extensions import Self

from .evm_log_decoder import NeonEvmLogDecoder, NeonTxLogInfo, NeonTxLogReturnInfo, NeonTxEventModel
from .neon_program import NeonProg
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddress, EthAddressField
from ..solana.alt_program import SolAltIxCode, SolAltProg
from ..solana.log_tree_decoder import SolTxIxLogInfo
from ..solana.pubkey import SolPubKey, SolPubKeyField
from ..solana.signature import SolTxSig, SolTxSigField
from ..solana.transaction_decoder import SolTxIxMetaInfo, SolTxMetaInfo, SolTxCostModel
from ..utils.cached import cached_method, cached_property
from ..utils.format import str_fmt_object
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class SolNeonTxIxMetaModel(BaseModel):
    sol_tx_sig: SolTxSigField
    slot: int
    sol_ix_idx: int
    sol_inner_ix_idx: int | None
    sol_tx_cost: SolTxCostModel
    neon_ix_code: int
    is_success: bool

    neon_tx_hash: EthTxHashField
    neon_tx_ix_miner: EthAddressField
    neon_step_cnt: int
    neon_total_step_cnt: int
    neon_gas_used: int
    neon_total_gas_used: int

    heap_size: int
    used_heap_size: int

    cu_limit: int
    used_cu_limit: int

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class SolNeonAltTxIxModel(BaseModel):
    sol_tx_sig: SolTxSigField
    slot: int
    sol_ix_idx: int
    sol_inner_ix_idx: int | None
    is_success: bool
    sol_tx_cost: SolTxCostModel

    alt_ix_code: SolAltIxCode
    alt_address: SolPubKeyField
    neon_tx_hash: EthTxHashField

    @classmethod
    def from_raw(cls, tx: SolTxMetaInfo, tx_ix: SolTxIxMetaInfo, neon_tx_hash: EthTxHash) -> Self | None:
        if tx_ix.prog_id != SolAltProg.ID:
            return None

        try:
            alt_ix_code = SolAltIxCode(int.from_bytes(tx_ix.sol_ix_data[:4], "little"))
            alt_address = tx_ix.account_key_list[0]
        except BaseException as exc:
            _LOG.error("error on decode AddressLookupTable ix: %s", exc, exc_info=exc)
            return None

        return cls(
            sol_tx_sig=tx.sol_tx_sig,
            slot=tx.slot,
            sol_ix_idx=tx_ix.sol_ix_idx,
            sol_inner_ix_idx=tx_ix.sol_inner_ix_idx,
            sol_tx_cost=tx.sol_tx_cost,
            is_success=tx_ix.is_success,
            alt_ix_code=alt_ix_code,
            alt_address=alt_address,
            neon_tx_hash=neon_tx_hash,
        )


@dataclass(frozen=True)
class SolNeonTxIxMetaInfo:
    neon_ix_code: int
    neon_ix_data: bytes

    heap_size: int
    used_heap_size: int
    cu_limit: int
    used_cu_limit: int

    # protected:
    _neon_log: NeonTxLogInfo
    _sol_tx: SolTxMetaInfo
    _sol_tx_ix: SolTxIxMetaInfo

    @classmethod
    def from_raw(cls, sol_tx: SolTxMetaInfo, sol_tx_ix: SolTxIxMetaInfo, sol_log: SolTxIxLogInfo) -> Self:
        neon_log = NeonEvmLogDecoder().decode(sol_tx_ix, sol_log.log_msg_list())
        ix_code, ix_data = cls._decode_ix_data(sol_tx_ix)

        return cls(
            neon_ix_code=ix_code,
            neon_ix_data=ix_data,
            heap_size=sol_tx.sol_tx_cu.heap_size,
            used_heap_size=sol_tx.sol_tx_cu.heap_size,
            cu_limit=sol_log.cu_limit or sol_tx.sol_tx_cu.cu_limit,
            used_cu_limit=sol_log.used_cu_limit or sol_tx.sol_tx_cu.cu_limit,
            #
            # protected:
            _neon_log=neon_log,
            _sol_tx=sol_tx,
            _sol_tx_ix=sol_tx_ix,
        )

    @property
    def ident(self):
        return self._sol_tx_ix.ident

    @property
    def sol_tx_sig(self) -> SolTxSig:
        return self._sol_tx_ix.sol_tx_sig

    @property
    def sol_tx_cost(self) -> SolTxCostModel:
        return self._sol_tx.sol_tx_cost

    @property
    def slot(self) -> int:
        return self._sol_tx_ix.slot

    @property
    def sol_ix_idx(self) -> int:
        return self._sol_tx_ix.sol_ix_idx

    @property
    def sol_inner_ix_idx(self) -> int | None:
        return self._sol_tx_ix.sol_inner_ix_idx

    @property
    def operator(self) -> SolPubKey:
        return self._sol_tx.sol_signer

    @property
    def is_success(self) -> bool:
        return self._sol_tx.is_success

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self._neon_log.neon_tx_hash

    @property
    def neon_tx_ix_miner(self) -> EthAddress:
        return self._neon_log.tx_ix_miner

    @property
    def neon_tx_ix_step_cnt(self) -> int:
        return self._neon_log.tx_ix_step.step_cnt

    @property
    def neon_total_step_cnt(self) -> int:
        return self._neon_log.tx_ix_step.total_step_cnt

    @property
    def neon_tx_ix_gas_used(self) -> int:
        return self._neon_log.tx_ix_gas.gas_used

    @property
    def neon_total_gas_used(self) -> int:
        return self._neon_log.tx_ix_gas.total_gas_used

    @property
    def neon_tx_ix_priority_fee(self) -> int:
        return self._neon_log.tx_ix_priority_fee.priority_fee_paid

    def to_string(self) -> str:
        return self._sol_tx_ix.to_string()

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        return isinstance(other, self.__class__) and (self.ident == other.ident)

    @cached_property
    def req_id(self) -> str:
        return "_".join(str(s)[:10] for s in self.ident)

    @property
    def neon_tx_return(self) -> NeonTxLogReturnInfo:
        return self._neon_log.tx_return

    @property
    def iter_neon_tx_event(self) -> Iterator[NeonTxEventModel]:
        return iter(self._neon_log.tx_event_list)

    @property
    def is_log_truncated(self) -> bool:
        return self._neon_log.is_truncated

    @property
    def is_already_finalized(self) -> bool:
        return self._neon_log.is_already_finalized

    @property
    def account_key_cnt(self) -> int:
        return len(self._sol_tx_ix.account_key_list)

    def get_account_key(self, idx: int) -> SolPubKey:
        acct_list = self._sol_tx_ix.account_key_list
        if len(acct_list) > idx:
            return acct_list[idx]
        return SolPubKey.default()

    def iter_alt_address(self) -> Iterator[SolPubKey]:
        return iter(self._sol_tx.alt_address_list)

    # protected:

    @classmethod
    def _decode_ix_data(cls, sol_tx_ix: SolTxIxMetaInfo) -> tuple[int, bytes]:
        try:
            if ix_data := sol_tx_ix.sol_ix_data:
                return int(ix_data[0]), ix_data
            else:
                return -1, bytes()
        except BaseException as exc:
            _LOG.error(f"%s: fail to get a program ix data", str(sol_tx_ix), exc_info=exc)
            return -1, bytes()


@dataclass(frozen=True)
class SolNeonTxMetaInfo:
    _sol_tx: SolTxMetaInfo

    @classmethod
    def from_raw(cls, sol_tx: SolTxMetaInfo) -> Self:
        return cls(_sol_tx=sol_tx)

    def to_string(self) -> str:
        return self._sol_tx.to_string()

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def sol_neon_ix_list(self) -> tuple[SolNeonTxIxMetaInfo, ...]:
        def _new_sol_neon_ix(_sol_tx_ix: SolTxIxMetaInfo) -> SolNeonTxIxMetaInfo | None:
            if (_sol_tx_ix.prog_id != NeonProg.ID) or (not _sol_tx_ix.has_sol_ix_data):
                return None

            sol_log = self._sol_tx.sol_ix_log_list(_sol_tx_ix)
            return SolNeonTxIxMetaInfo.from_raw(self._sol_tx, _sol_tx_ix, sol_log)

        try:
            sol_neon_ix_list: list[SolNeonTxIxMetaInfo] = list()
            for sol_tx_ix in self._sol_tx.sol_ix_list:
                if sol_neon_ix := _new_sol_neon_ix(sol_tx_ix):
                    sol_neon_ix_list.append(sol_neon_ix)

                for sol_tx_inner_ix in self._sol_tx.sol_inner_ix_list(sol_tx_ix):
                    if sol_neon_ix := _new_sol_neon_ix(sol_tx_inner_ix):
                        sol_neon_ix_list.append(sol_neon_ix)

            return tuple(sol_neon_ix_list)

        except BaseException as exc:
            _LOG.error("error on decode Neon ix", exc_info=exc)

        return tuple()

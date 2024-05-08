from __future__ import annotations

import logging
import typing
from dataclasses import dataclass

import base58
from typing_extensions import Self

from .cb_program import SolCuIxCode, SolCbProg
from .log_tree_decoder import SolTxIxLogInfo, SolTxLogTreeInfo, SolTxLogTreeDecoder
from .pubkey import SolPubKey, SolPubKeyField
from .signature import SolTxSig, SolTxSigField
from .transaction import SolTxMessageInfo
from .transaction_meta import SolRpcTxInfo, SolRpcTxMetaInfo, SolRpcTxIxInfo
from ..utils.cached import cached_method, cached_property
from ..utils.format import str_fmt_object
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolTxMetaInfo:
    slot: int
    sol_tx_sig: SolTxSig

    # protected:
    _rpc_message: SolTxMessageInfo
    _rpc_meta: SolRpcTxMetaInfo

    @classmethod
    def from_raw(cls, slot: int, rpc_tx: SolRpcTxInfo) -> Self:
        return cls(
            slot=slot,
            sol_tx_sig=SolTxSig.from_raw(rpc_tx.transaction.signatures[0]),
            #
            # protected:
            _rpc_message=typing.cast(SolTxMessageInfo, rpc_tx.transaction.message),
            _rpc_meta=rpc_tx.meta,
        )

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_property
    def is_success(self) -> bool:
        return self._rpc_meta.err is None

    @cached_property
    def sol_ix_list(self) -> tuple[SolTxIxMetaInfo, ...]:
        raw_ix_list = self._rpc_message.instructions
        return tuple([SolTxIxMetaInfo.from_raw(self, idx, None, ix) for idx, ix in enumerate(raw_ix_list)])

    def sol_inner_ix_list(self, tx_ix: SolTxIxMetaInfo) -> tuple[SolTxIxMetaInfo, ...]:
        inner_ix_list = self._inner_ix_list
        if tx_ix.sol_ix_idx >= len(inner_ix_list):
            _LOG.error("%s: cannot find an inner ix %s", self.to_string(), tx_ix.sol_ix_idx)
            return tuple()

        return inner_ix_list[tx_ix.sol_ix_idx]

    def sol_ix_log_list(self, tx_ix: SolTxIxMetaInfo) -> SolTxIxLogInfo:
        tx_log_tree = self._tx_log_tree
        if tx_ix.sol_ix_idx > len(tx_log_tree.log_list):
            _LOG.error("%s: cannot find logs for ix %s", self.to_string(), tx_ix.sol_ix_idx)
            return SolTxIxLogInfo.new_unknown()

        ix_log: SolTxIxLogInfo = tx_log_tree.log_list[tx_ix.sol_ix_idx]
        if tx_ix.sol_inner_ix_idx is None:
            return ix_log
        elif tx_ix.sol_inner_ix_idx > len(ix_log.inner_log_list):
            _LOG.error("%s: cannot find logs for ix %s:%s", self.to_string(), tx_ix.sol_ix_idx, tx_ix.sol_inner_ix_idx)
            return SolTxIxLogInfo.new_unknown()
        return ix_log.inner_log_list[tx_ix.sol_inner_ix_idx]

    @cached_property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        key_list = list(map(lambda a: SolPubKey.from_raw(a), self._rpc_message.account_keys))
        loaded_addr_list = self._rpc_meta.loaded_addresses
        if loaded_addr_list is not None:
            key_list.extend(map(lambda a: SolPubKey.from_raw(a), loaded_addr_list.writable))
            key_list.extend(map(lambda a: SolPubKey.from_raw(a), loaded_addr_list.readonly))
        return tuple(key_list)

    @cached_property
    def alt_address_list(self) -> tuple[SolPubKey, ...]:
        alt_list = getattr(self._rpc_message, "address_table_lookups", tuple())
        return tuple(map(lambda a: SolPubKey.from_raw(a.account_key), alt_list))

    @cached_property
    def sol_signer(self) -> SolPubKey:
        acct_list = self._rpc_message.account_keys
        if not acct_list:
            _LOG.error("%s: cannot find signer", self.to_string())
            return SolPubKey.default()
        return SolPubKey.from_raw(acct_list[0])

    @cached_property
    def sol_tx_cost(self) -> SolTxCostModel:
        return SolTxCostModel.from_raw(self, self._rpc_meta)

    @cached_property
    def sol_tx_cu(self) -> SolTxCuInfo:
        return SolTxCuInfo.from_raw(self)

    # protected:

    @cached_property
    def _inner_ix_list(self) -> tuple[tuple[SolTxIxMetaInfo, ...], ...]:
        raw_inner_ix_list = self._rpc_meta.inner_instructions
        if raw_inner_ix_list is None:
            return tuple()

        inner_ix_list: list[tuple[SolTxIxMetaInfo, ...]] = [tuple() for _ in self.sol_ix_list]
        for raw_inner_ix in raw_inner_ix_list:
            idx = raw_inner_ix.index
            raw_ix_list = raw_inner_ix.instructions
            ix_list = tuple(
                [SolTxIxMetaInfo.from_raw(self, idx, inner_idx, ix) for inner_idx, ix in enumerate(raw_ix_list)]
            )
            inner_ix_list[idx] = ix_list
        return tuple(inner_ix_list)

    @cached_property
    def _tx_log_tree(self) -> SolTxLogTreeInfo:
        return SolTxLogTreeDecoder.decode(self._rpc_message, self._rpc_meta, self.account_key_list)


@dataclass(frozen=True)
class SolTxIxMetaInfo:
    sol_tx_sig: SolTxSig
    slot: int
    sol_ix_idx: int
    sol_inner_ix_idx: int | None
    is_success: bool

    # protected:
    _rpc_tx_ix: SolRpcTxIxInfo
    _tx_acct_key_list: tuple[SolPubKey, ...]

    @classmethod
    def from_raw(cls, tx: SolTxMetaInfo, idx: int, inner_idx: int | None, tx_ix: SolRpcTxIxInfo) -> Self:
        return cls(
            sol_tx_sig=tx.sol_tx_sig,
            slot=tx.slot,
            sol_ix_idx=idx,
            sol_inner_ix_idx=inner_idx,
            is_success=tx.is_success,
            #
            # protected:
            _rpc_tx_ix=tx_ix,
            _tx_acct_key_list=tx.account_key_list,
        )

    @cached_method
    def to_string(self) -> str:
        return ":".join(str(s) for s in self.ident)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_property
    def ident(self) -> tuple[str, int, int] | tuple[str, int, int, int]:
        if self.sol_inner_ix_idx is None:
            return self.sol_tx_sig.to_string(), self.slot, self.sol_ix_idx
        else:
            return self.sol_tx_sig.to_string(), self.slot, self.sol_ix_idx, self.sol_inner_ix_idx

    @cached_property
    def sol_ix_data(self) -> bytes:
        data = self._rpc_tx_ix.data
        if isinstance(data, str):
            data = base58.b58decode(data)
        return data

    @property
    def has_sol_ix_data(self) -> bool:
        return len(self.sol_ix_data) > 1

    @cached_property
    def prog_id(self) -> SolPubKey:
        return self._tx_acct_key_list[self._rpc_tx_ix.program_id_index]

    @cached_property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple([self._tx_acct_key_list[idx] for idx in self._rpc_tx_ix.accounts])


class SolTxCostModel(BaseModel):
    sol_tx_sig: SolTxSigField
    slot: int
    is_success: bool

    sol_operator: SolPubKeyField
    sol_spent: int

    @classmethod
    def from_raw(cls, tx: SolTxMetaInfo, rpc_meta: SolRpcTxMetaInfo) -> Self:
        pre_balance_list = rpc_meta.pre_balances
        post_balance_list = rpc_meta.post_balances

        pre_balance = pre_balance_list[0] if pre_balance_list else 0
        post_balance = post_balance_list[0] if post_balance_list else 0

        return cls(
            sol_tx_sig=tx.sol_tx_sig,
            slot=tx.slot,
            is_success=tx.is_success,
            sol_operator=tx.sol_signer,
            sol_spent=(pre_balance - post_balance),
        )


@dataclass(frozen=True)
class SolTxCuInfo:
    sol_tx_sig: SolTxSig
    slot: int

    heap_size: int
    cu_limit: int
    cu_price: int

    @classmethod
    def from_raw(cls, tx: SolTxMetaInfo) -> Self:
        heap_size = 32 * 1024
        cu_limit = 200_000
        cu_price = 0

        for tx_ix in tx.sol_ix_list:
            if tx_ix.prog_id != SolCbProg.ID:
                continue

            try:
                ix_data = tx_ix.sol_ix_data
                ix_code = ix_data[0]
                ix_data = ix_data[1:]
                if ix_code == SolCuIxCode.HeapSize:
                    heap_size = int.from_bytes(ix_data, "little")
                elif ix_code == SolCuIxCode.CuLimit:
                    cu_limit = int.from_bytes(ix_data, "little")
                elif ix_code == SolCuIxCode.CuPrice:
                    cu_price = int.from_bytes(ix_data, "little")
            except BaseException as exc:
                _LOG.error("error on decode ComputeBudget ix", exc_info=exc)
                continue

        return cls(
            sol_tx_sig=tx.sol_tx_sig,
            slot=tx.slot,
            heap_size=heap_size,
            cu_limit=cu_limit,
            cu_price=cu_price,
        )

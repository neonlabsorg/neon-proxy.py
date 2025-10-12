from __future__ import annotations

import asyncio
import enum
import logging
import time
from typing import Final, Sequence

from common.config.config import Config
from common.config.constants import ONE_BLOCK_SEC, MIN_FINALIZE_SEC
from common.ethereum.hash import EthAddress
from common.neon.address import NeonAddress
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api_client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from common.solana_rpc.ws_client import SolWatchAccountSession
from common.utils.cached import cached_method, reset_cached_method, cached_property
from common.utils.json_logger import logging_context, log_msg
from .sender_nonce import SenderNonce
from .sorted_queue import SortedQueue
from .transaction_dict import MpTxDict
from ..base.mp_api import (
    MpTxModel,
    MpTxRespCode,
    MpTxResp,
    MpTxPoolContentResp,
    MpTxStatusModel,
    MpTxExecPctModel,
    MpTxStatusListResp,
)

_LOG = logging.getLogger(__name__)


class _TxDict:
    _top_index = -1

    def __init__(self, chain_id: int, global_tx_dict: MpTxDict) -> None:
        self._chain_id = chain_id
        self._global_tx_dict = global_tx_dict
        self._tx_dict: dict[SenderNonce, MpTxModel] = dict()
        self._tx_gas_price_queue = SortedQueue[MpTxModel, int, str](
            lt_key_func=lambda a: -a.gas_price,
            eq_key_func=lambda a: a.neon_tx_hash,
        )
        self._tx_gapped_gas_price_queue = SortedQueue[MpTxModel, int, str](
            lt_key_func=lambda a: -a.gas_price,
            eq_key_func=lambda a: a.neon_tx_hash,
        )

    def __len__(self) -> int:
        return len(self._tx_dict)

    @property
    def len_tx_gas_price_queue(self) -> int:
        return len(self._tx_gas_price_queue)

    def add_tx(self, tx: MpTxModel, is_gapped_tx: bool) -> None:
        sender_nonce = SenderNonce.from_raw(tx)
        assert sender_nonce not in self._tx_dict, f"Tx {sender_nonce} is already in dictionary"
        # assert tx not in self._tx_gas_price_queue, f"Tx {tx.neon_tx_hash} is already in gas price queue"
        # assert tx not in self._tx_gapped_gas_price_queue, f"Tx {tx.neon_tx_hash} is already in gapped gas price queue"

        self._tx_dict[sender_nonce] = tx
        self._global_tx_dict.add_tx(tx)

        if is_gapped_tx:
            self._tx_gapped_gas_price_queue.add(tx)
        else:
            self._tx_gas_price_queue.add(tx)
            self.queue_tx(tx.sender, tx.nonce + 1)

        assert len(self._tx_dict) >= (len(self._tx_gas_price_queue) + len(self._tx_gapped_gas_price_queue))

    def pop_tx(self, tx: MpTxModel) -> MpTxModel:
        sender_nonce = SenderNonce.from_raw(tx)
        assert sender_nonce in self._tx_dict, f"Tx {sender_nonce} is absent in dictionary"

        # tx may be removed from the gas price queue on processing
        if (pos := self._tx_gapped_gas_price_queue.find(tx)) is not None:
            self._tx_gapped_gas_price_queue.pop(pos)
        else:
            self._tx_gas_price_queue.pop(tx)
            self.dequeue_tx(tx.sender, tx.nonce + 1)

        self._global_tx_dict.pop_tx(tx.neon_tx_hash)
        return self._tx_dict.pop(sender_nonce)

    def pop_tx_list(self, tx_list: Sequence[MpTxModel]) -> None:
        for tx in tx_list:
            old_tx = self._tx_dict.pop(SenderNonce.from_raw(tx), None)
            assert old_tx, f"Tx {tx} is absent in dictionary"
            self._global_tx_dict.pop_tx(tx.neon_tx_hash)

            if (pos := self._tx_gapped_gas_price_queue.find(tx)) is not None:
                self._tx_gapped_gas_price_queue.pop(pos)
            else:
                self._tx_gas_price_queue.pop(tx)

    def done_tx(self, tx: MpTxModel) -> MpTxModel:
        """Tx was in the processing,"""
        sender_nonce = SenderNonce.from_raw(tx)
        assert sender_nonce in self._tx_dict, f"Tx {sender_nonce} is absent in dictionary"
        # assert tx not in self._tx_gas_price_queue
        # assert tx not in self._tx_gapped_gas_price_queue
        self._global_tx_dict.done_tx(tx.neon_tx_hash)
        return self._tx_dict.pop(sender_nonce)

    def _move_between_gas_price_queues(
        self,
        src: SortedQueue[MpTxModel, int, str],
        dst: SortedQueue[MpTxModel, int, str],
        sender: EthAddress,
        nonce: int,
    ) -> None:
        while tx := self._tx_dict.get(SenderNonce.from_raw((sender, self._chain_id, nonce)), None):
            if (pos := src.find(tx)) is None:
                break
            dst.add(src.pop(pos))
            nonce += 1

    def get_tx(self, sender: EthAddress, tx_nonce: int) -> MpTxModel | None:
        sender_nonce = SenderNonce.from_raw((sender, self._chain_id, tx_nonce))
        return self._tx_dict.get(sender_nonce, None)

    def acquire_tx(self, tx: MpTxModel) -> None:
        self._tx_gas_price_queue.pop(tx)

    def cancel_process_tx(self, tx: MpTxModel) -> None:
        self._tx_gas_price_queue.add(tx)

    def queue_tx(self, sender: EthAddress, start_nonce: int) -> None:
        self._move_between_gas_price_queues(
            self._tx_gapped_gas_price_queue,
            self._tx_gas_price_queue,
            sender,
            start_nonce,
        )

    def dequeue_tx(self, sender: EthAddress, start_nonce: int) -> None:
        self._move_between_gas_price_queues(
            self._tx_gas_price_queue,
            self._tx_gapped_gas_price_queue,
            sender,
            start_nonce,
        )

    def peek_gapped_lower_tx(self) -> MpTxModel | None:
        return self._tx_gapped_gas_price_queue[self._top_index] if self._tx_gapped_gas_price_queue else None

    def peek_pending_lower_tx(self) -> MpTxModel | None:
        return self._tx_gas_price_queue[self._top_index] if self._tx_gas_price_queue else None

    def peek_lower_tx(self) -> MpTxModel | None:
        return self.peek_gapped_lower_tx() or self.peek_pending_lower_tx()


class _SenderTxPool:
    _top_index: Final[int] = -1
    _bottom_index: Final[int] = 0

    class Status(enum.IntEnum):
        Empty = 1
        Suspended = 2
        Queued = 3
        Processing = 4

    def __init__(self, sender: EthAddress, chain_id: int) -> None:
        self._status = self.Status.Empty
        self._sender: Final[EthAddress] = sender
        self._chain_id: Final[int] = chain_id
        self._sol_addr = SolPubKey.default()
        self._gas_price = 0
        self._heartbeat_sec = int(time.monotonic())
        self._state_tx_cnt = 0
        self._balance = 0
        self._processing_tx: MpTxModel | None = None
        self._tx_nonce_queue = SortedQueue[MpTxModel, int, str](
            lt_key_func=lambda a: -a.nonce,
            eq_key_func=lambda a: a.neon_tx_hash,
        )

    @cached_method
    def to_string(self) -> str:
        return f"{self._sender.to_string()}:0x{self._chain_id:x}:0x{self._state_tx_cnt:x}:0x{self._balance:x}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def __hash__(self) -> int:
        return hash(self._sender)

    def __eq__(self, other: _SenderTxPool) -> bool:
        return other._sender == self._sender

    @property
    def sender(self) -> EthAddress:
        return self._sender

    @property
    def sol_address(self) -> SolPubKey:
        return self._sol_addr

    def set_sol_address(self, sol_addr: SolPubKey) -> None:
        self._sol_addr = sol_addr

    @property
    def gas_price(self) -> int:
        return self._gas_price

    @property
    def status(self) -> _SenderTxPool.Status:
        return self._status

    def sync_status(self) -> _SenderTxPool.Status:
        self._status = self._actual_status
        top_tx = self.top_tx
        self._gas_price = top_tx.gas_price if top_tx else 0
        self._get_pending_tx_cnt.reset_cache(self)
        return self._status

    @property
    def has_valid_status(self) -> bool:
        return self._actual_status == self._status

    @property
    def is_empty(self) -> bool:
        return self.tx_cnt == 0

    @property
    def is_processing(self) -> bool:
        return self._processing_tx is not None

    @property
    def tx_cnt(self) -> int:
        return len(self._tx_nonce_queue)

    def add_tx(self, tx: MpTxModel) -> None:
        assert (
            self._state_tx_cnt <= tx.nonce
        ), f"Tx {tx.neon_tx_hash} has nonce {tx.nonce} less than {self._state_tx_cnt}"
        self._tx_nonce_queue.add(tx)
        self._heartbeat_sec = int(time.monotonic())
        # _LOG.debug(self._log_action("add tx", tx))

    @property
    def top_tx(self) -> MpTxModel | None:
        return self._tx_nonce_queue[self._top_index] if not self.is_empty else None

    def acquire_tx(self, tx: MpTxModel) -> MpTxModel:
        assert not self.is_processing
        assert tx.neon_tx_hash == self.top_tx.neon_tx_hash

        self._processing_tx = self.top_tx
        self._status = self.Status.Processing
        return self._processing_tx

    @property
    def pending_tx_cnt(self) -> int | None:
        return self._get_pending_tx_cnt()

    @reset_cached_method
    def _get_pending_tx_cnt(self) -> int:
        return self.get_pending_tx_cnt(0)

    def get_pending_tx_cnt(self, base_tx_cnt: int) -> int | None:
        if self.status in (self.Status.Suspended, self.Status.Empty):
            # _LOG.debug("status = %s", self.status)
            return None

        pending_tx_cnt = max(self._state_tx_cnt, base_tx_cnt)
        # _LOG.debug(
        #     "sender %s: state_tx_cnt = %s, pending_tx_cnt = %s",
        #     self._sender,
        #     self._state_tx_cnt,
        #     self.len_tx_nonce_queue,
        # )
        for tx in reversed(self._tx_nonce_queue):
            if tx.nonce != pending_tx_cnt:
                # _LOG.debug(
                #     "sender %s: tx.nonce(%s) != pending_tx_cnt(%s), state_tx_cnt %s",
                #     self._sender,
                #     tx.nonce,
                #     pending_tx_cnt,
                #     self.len_tx_nonce_queue,
                #     self._state_tx_cnt,
                # )
                break
            pending_tx_cnt += 1
        return pending_tx_cnt

    @property
    def state_tx_cnt(self) -> int:
        if self.is_processing:
            assert self._state_tx_cnt == self._processing_tx.nonce
            return self._processing_tx.nonce + 1
        return self._state_tx_cnt

    @property
    def balance(self) -> int:
        return self._balance

    def set_sender_state(self, state_tx_cnt: int, balance: int) -> None:
        if not self.is_processing:
            self._state_tx_cnt = state_tx_cnt
            self._balance = balance

    @property
    def heartbeat_sec(self) -> int:
        return self._heartbeat_sec

    def done_tx(self, tx: MpTxModel) -> None:
        self._validate_processing_tx(tx)

        self._tx_nonce_queue.pop(self._top_index)
        self._processing_tx = None
        # _LOG.debug(self._log_action("done tx", tx))

    def drop_tx(self, tx: MpTxModel) -> None:
        assert (
            not self.is_processing or tx.neon_tx_hash != self._processing_tx.neon_tx_hash
        ), f"cannot drop processing tx {tx.neon_tx_hash}"

        self._tx_nonce_queue.pop(tx)
        # _LOG.debug(self._log_action("drop tx", tx))

    def cancel_process_tx(self, tx: MpTxModel) -> None:
        self._validate_processing_tx(tx)
        self._processing_tx = None

    @property
    def pending_stop_pos(self) -> int:
        if self.status in (self.Status.Suspended, self.Status.Empty):
            return 0

        pending_pos, pending_nonce = 0, self._state_tx_cnt
        for tx in reversed(self._tx_nonce_queue):
            if tx.nonce != pending_nonce:
                break
            pending_nonce += 1
            pending_pos += 1
        return pending_pos

    def tx_list(self) -> list[MpTxModel]:
        return self._tx_nonce_queue.queue()

    def pop_tx_list(self) -> list[MpTxModel]:
        return self._tx_nonce_queue.pop_queue()

    def info(self) -> dict:
        return dict(TxCnt=self.tx_cnt, Sender=self, StateTxCnt=hex(self.state_tx_cnt), NextTx=self.top_tx)

    # protected:

    def _validate_processing_tx(self, tx: MpTxModel) -> None:
        assert not self.is_empty, f"no transactions in {self.sender} pool"
        assert self.is_processing, f"{self.sender} pool does not process tx {tx.neon_tx_hash}"

        t_tx, p_tx = self.top_tx, self._processing_tx
        assert (
            tx.neon_tx_hash == p_tx.neon_tx_hash
        ), f"tx {tx.neon_tx_hash} is not equal to processing tx {p_tx.neon_tx_hash}"
        assert t_tx is p_tx, f"top tx {t_tx.neon_tx_hash} is not equal to processing tx {p_tx.neon_tx_hash}"

    @property
    def _actual_status(self) -> _SenderTxPool.Status:
        if self.is_empty:
            return self.Status.Empty
        elif self.is_processing:
            return self.Status.Processing

        if (self._state_tx_cnt != self.top_tx.nonce) or (not self._has_sufficient_balance):
            return self.Status.Suspended
        return self.Status.Queued

    @property
    def _has_sufficient_balance(self) -> bool:
        top_tx = self.top_tx
        if top_tx.neon_tx.is_scheduled_tx:
            return True
        return top_tx.neon_tx.cost <= self._balance

    def _log_action(self, msg: str, tx: MpTxModel) -> dict:
        return log_msg(
            f"{msg} " "{Tx}, {Sender} pool has {TxCnt} txs, tx counter {StateTxCnt}, next tx {NextTx}",
            Tx=tx,
            **self.info(),
        )


class MpTxSchedule:
    _top_index: Final[int] = -1

    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        core_api_client: CoreApiClient,
        token: str,
        chain_id: int,
        global_tx_dict: MpTxDict,
    ) -> None:
        self._core_api_client = core_api_client
        self._watch_session = SolWatchAccountSession(cfg, sol_client, force_check_sec=MIN_FINALIZE_SEC)
        self._capacity: Final[int] = cfg.mp_capacity
        self._capacity_high_watermark: Final[int] = int(self._capacity * cfg.mp_capacity_high_watermark)
        self._eviction_timeout_sec = cfg.mp_eviction_timeout_sec

        self._tx_dict = _TxDict(chain_id, global_tx_dict)
        self._global_tx_dict = global_tx_dict
        self._token: Final[str] = token
        self._chain_id: Final[int] = chain_id

        self._sender_pool_dict: dict[EthAddress, _SenderTxPool] = dict()
        self._sol_sender_pool_dict: dict[SolPubKey, _SenderTxPool] = dict()
        self._sender_pool_heartbeat_queue = SortedQueue[_SenderTxPool, int, str](
            lt_key_func=lambda a: -a.heartbeat_sec,
            eq_key_func=lambda a: a.sender,
        )
        self._sender_pool_queue = SortedQueue[_SenderTxPool, int, str](
            lt_key_func=lambda a: a.gas_price,
            eq_key_func=lambda a: a.sender,
        )
        self._suspended_sender_set: set[EthAddress] = set()
        self._sub_sender_set: set[_SenderTxPool] = set()

        self._stop_event = asyncio.Event()
        self._heartbeat_task: asyncio.Task | None = None
        self._update_state_tx_cnt_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._update_state_tx_cnt_task = asyncio.create_task(self._update_state_tx_cnt_loop())

    async def stop(self) -> None:
        self._stop_event.set()

        if self._heartbeat_task:
            await self._heartbeat_task

        if self._update_state_tx_cnt_task:
            await self._update_state_tx_cnt_task

    @property
    def min_gas_price(self) -> int:
        if self.tx_cnt < self._capacity_high_watermark:
            return 0

        lower_tx = self._tx_dict.peek_pending_lower_tx()
        if not lower_tx:
            return 0
        return int(lower_tx.gas_price * 1.3)  # increase gas-price in 30%

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def token(self) -> str:
        return self._token

    def add_tx(self, tx: MpTxModel, state_tx_cnt: int, balance: int) -> MpTxResp:
        # _LOG.debug(log_msg("add tx {Tx} to mempool {ChainID} with {TxCnt}({PendingTxCnt}) txs", Tx=tx, **self._info()))

        def _is_higher_gas_price(_hdr: str, _old_tx: MpTxModel | None) -> MpTxResp | None:
            if not _old_tx:
                return None
            # force replacing of scheduled txs
            elif _old_tx.neon_tx.is_scheduled_tx and tx.neon_tx.is_scheduled_tx:
                return None
            elif _old_tx.gas_price >= tx.gas_price:
                _msg = log_msg(
                    _hdr + " tx {OldTx} has higher gas-price than {GasPrice}",
                    OldTx=_old_tx,
                    GasPrice=tx.gas_price,
                )
                _LOG.debug(_msg)
                return MpTxResp(code=MpTxRespCode.Underprice, state_tx_cnt=None)
            return None

        old_tx = self._tx_dict.get_tx(tx.sender, tx.nonce)
        if old_tx:
            if old_tx.neon_tx_hash == tx.neon_tx_hash:
                _LOG.debug(log_msg("tx {Tx} is already scheduled", Tx=tx))
                return MpTxResp(code=MpTxRespCode.AlreadyKnown, state_tx_cnt=None)
            elif resp := _is_higher_gas_price("old", old_tx):
                return resp

        pool = self._get_or_create_sender_pool(tx.sender)

        # pool.state_tx_cnt returns (state_tx_cnt +  1), if it has a processing tx
        state_tx_cnt = max(state_tx_cnt, pool.state_tx_cnt)

        if self.tx_cnt >= self._capacity_high_watermark:
            gapped_tx = self._tx_dict.peek_gapped_lower_tx()
            if (pool.pending_tx_cnt or state_tx_cnt) < tx.nonce:
                if not gapped_tx:
                    return MpTxResp(code=MpTxRespCode.NonceTooHigh, state_tx_cnt=state_tx_cnt)
                elif resp := _is_higher_gas_price("lowermost gapped", gapped_tx):
                    return resp
            elif (self.tx_cnt >= self._capacity) and (not gapped_tx):
                pending_tx = self._tx_dict.peek_pending_lower_tx()
                if resp := _is_higher_gas_price("lowermost pending", pending_tx):
                    return resp

        if pool.is_processing:
            top_tx = pool.top_tx
            if top_tx.nonce == tx.nonce:
                _LOG.debug(log_msg("tx {OldTx} is processing", OldTx=top_tx))
                return MpTxResp(code=MpTxRespCode.NonceTooLow, state_tx_cnt=top_tx.nonce + 1)

        if state_tx_cnt > tx.nonce:
            msg = log_msg(
                "sender {Sender} has higher tx counter {StateTxCnt} > {Nonce}",
                Sender=pool,
                StateTxCnt=hex(state_tx_cnt),
                Nonce=hex(tx.nonce),
            )
            _LOG.debug(msg)
            return MpTxResp(code=MpTxRespCode.NonceTooLow, state_tx_cnt=state_tx_cnt)

        # Everything is ok, let's add transaction to the pool
        if old_tx:
            with logging_context(tx=old_tx.tx_id):
                _LOG.debug(log_msg("replace tx {OldTx} with tx {Tx}", OldTx=old_tx, Tx=tx))
                self._drop_tx_from_sender_pool(pool, old_tx)

        self._check_oversized_and_reduce()
        self._add_tx_to_sender_pool(pool, tx)
        self._schedule_sender_pool(pool, state_tx_cnt, balance)

        msg = log_msg(
            "add tx {Tx} to sender {Pool}, mempool {ChainID} has {TxCnt}({PendingTxCnt}) txs",
            Tx=tx,
            Pool=pool,
            **self._info(),
        )
        _LOG.debug(msg)
        return MpTxResp(code=MpTxRespCode.Success, state_tx_cnt=None)

    def drop_tx(self, sender: EthAddress, nonce: int) -> bool:
        if not (tx := self._tx_dict.get_tx(sender, nonce)):
            return True

        pool = self._get_sender_pool(tx.sender)
        if pool.is_processing:
            # _LOG.debug(log_msg("cannot drop processing tx {Tx}", Tx=tx))
            return False

        self._drop_tx_from_sender_pool(pool, tx)
        self._schedule_sender_pool(pool, tx.nonce, pool.balance)
        return True

    @property
    def tx_cnt(self) -> int:
        return len(self._tx_dict)

    @cached_property
    def high_tx_cnt(self) -> int:
        return int(self.max_tx_cnt * 0.9)

    @property
    def max_tx_cnt(self) -> int:
        return self._capacity

    @property
    def pending_tx_cnt(self) -> int:
        return self._tx_dict.len_tx_gas_price_queue

    def peek_top_tx(self) -> MpTxModel | None:
        if not self._sender_pool_queue:
            return None
        return self._sender_pool_queue[self._top_index].top_tx

    def acquire_tx(self, tx: MpTxModel) -> None:
        pool = self._get_sender_pool(tx.sender)
        assert pool.status == pool.Status.Queued

        self._sender_pool_queue.pop(pool)
        pool.acquire_tx(tx)
        self._tx_dict.acquire_tx(tx)

    def get_pending_tx_cnt(self, sender: EthAddress, base_tx_cnt: int) -> int | None:
        pool = self._find_sender_pool(sender)
        return None if not pool else pool.get_pending_tx_cnt(base_tx_cnt)

    def get_tx_status_list(
        self,
        sender: EthAddress,
        state_tx_cnt: int,
        balance: int,
        min_exec_gas_price: int,
    ) -> MpTxStatusListResp:
        def get_exec_pct_list_(tx_: MpTxModel, is_done_: bool) -> list[MpTxExecPctModel]:
            nonlocal state_tx_cnt
            nonlocal in_processing

            if (tx_.nonce == state_tx_cnt) and in_processing:
                return self._global_tx_dict.get_exec_pct_list(tx_.neon_tx_hash)
            elif is_done_:
                return [MpTxExecPctModel(neon_tx_hash=tx_.neon_tx_hash, exec_pct=100)]
            return list()

        def new_tx_status_(tx_: MpTxModel, is_done_: bool) -> MpTxStatusModel:
            return MpTxStatusModel.from_raw(tx_, get_exec_pct_list_(tx_, is_done_))

        tx_status_list: list[MpTxStatusModel] = list()
        in_processing = False
        if pool := self._find_sender_pool(sender):
            self._schedule_sender_pool(pool, state_tx_cnt, balance)
            if not pool.is_empty:
                state_tx_cnt = pool.state_tx_cnt
                in_processing = pool.is_processing
                tx_status_list = [new_tx_status_(tx, False) for tx in pool.tx_list()]

        # Add the last 2 processed txs from the cache
        tx_nonce = (tx_status_list[-1].nonce if tx_status_list else state_tx_cnt) - 1
        min_tx_nonce = max(tx_nonce - 1, 0)
        sender = NeonAddress.from_raw(sender, self._chain_id)
        while tx_nonce >= min_tx_nonce:
            if tx := self._global_tx_dict.get_tx_by_sender_nonce(sender, tx_nonce):
                tx_status_list.append(new_tx_status_(tx, True))
                tx_nonce -= 1
            else:
                break

        return MpTxStatusListResp(
            state_tx_cnt=state_tx_cnt,
            balance=balance,
            min_exec_gas_price=min_exec_gas_price,
            in_processing=in_processing,
            tx_status_list=list(reversed(tx_status_list)),
        )

    def done_tx(self, tx: MpTxModel, state_tx_cnt: int, balance: int) -> None:
        # _LOG.debug(log_msg("done tx {Tx}", Tx=tx))
        self._done_tx(tx, state_tx_cnt, balance)

    def fail_tx(self, tx: MpTxModel, state_tx_cnt: int, balance: int) -> None:
        # _LOG.debug(log_msg("fail tx {Tx}", Tx=tx))
        self._done_tx(tx, state_tx_cnt, balance)

    def cancel_tx(self, tx: MpTxModel, state_tx_cnt: int, balance: int) -> bool:
        # _LOG.debug(log_msg("cancel tx {Tx}", Tx=tx))
        if not (pool := self._find_sender_pool(tx.sender)):
            _LOG.warning("pool %s doesn't exists", tx.sender)
            return False

        pool.cancel_process_tx(tx)
        self._tx_dict.cancel_process_tx(tx)

        self._schedule_sender_pool(pool, state_tx_cnt, balance)
        return True

    def get_content(self) -> MpTxPoolContentResp:
        pending_list: list[NeonTxModel] = list()
        queued_list: list[NeonTxModel] = list()

        for tx_pool in self._sender_pool_dict.values():
            tx_list = list(map(lambda tx: tx.neon_tx, reversed(tx_pool.tx_list())))
            pending_stop_pos = tx_pool.pending_stop_pos
            pending_list.extend(tx_list[:pending_stop_pos])
            queued_list.extend(tx_list[pending_stop_pos:])

        return MpTxPoolContentResp(pending_list=pending_list, queued_list=queued_list)

    # protected:

    def _info(self) -> dict:
        return dict(
            ChainID=hex(self._chain_id),
            TxCnt=self.tx_cnt,
            PendingTxCnt=self.pending_tx_cnt,
        )

    def _add_tx_to_sender_pool(self, pool: _SenderTxPool, tx: MpTxModel) -> None:
        if not (is_new_pool := pool.status == pool.Status.Empty):  # use old state, before remove old tx
            self._sender_pool_heartbeat_queue.pop(pool)

        is_gapped_tx = (pool.status in (pool.Status.Suspended, pool.Status.Empty)) or (pool.pending_tx_cnt < tx.nonce)
        pool.add_tx(tx)
        self._tx_dict.add_tx(tx, is_gapped_tx)

        # the first tx in the sender pool
        if is_new_pool:
            self._sender_pool_dict[pool.sender] = pool

        self._sender_pool_heartbeat_queue.add(pool)

    def _drop_tx_from_sender_pool(self, pool: _SenderTxPool, tx: MpTxModel) -> None:
        pool.drop_tx(tx)
        self._tx_dict.pop_tx(tx)

    def _find_sender_pool(self, sender: EthAddress) -> _SenderTxPool | None:
        return self._sender_pool_dict.get(sender, None)

    def _get_or_create_sender_pool(self, sender: EthAddress) -> _SenderTxPool:
        if pool := self._find_sender_pool(sender):
            # _LOG.debug(log_msg("find pool {Sender} with {TxCnt} txs", Sender=pool, TxCnt=pool.tx_cnt))
            pass
        else:
            pool = _SenderTxPool(sender, self._chain_id)
            # _LOG.debug(log_msg("create new pool {Sender}", Sender=pool))
        return pool

    def _get_sender_pool(self, sender: EthAddress) -> _SenderTxPool:
        pool = self._find_sender_pool(sender)
        assert pool, f"Failed to get sender tx pool by sender {sender}"
        return pool

    def _schedule_sender_pool(self, pool: _SenderTxPool, state_tx_cnt: int, balance: int) -> None:
        self._drop_old_tx_list(pool, state_tx_cnt)

        old_status = pool.status
        self._sync_sender_status(pool)
        pool.set_sender_state(state_tx_cnt, balance)
        self._sync_sender_status(pool)

        self._sub_update_sender(pool, old_status)

    def _drop_old_tx_list(self, pool: _SenderTxPool, state_tx_cnt: int) -> None:
        if pool.state_tx_cnt == state_tx_cnt:
            return
        elif pool.is_processing:
            return

        while top_tx := pool.top_tx:
            if top_tx.nonce >= state_tx_cnt:
                break
            self._drop_tx_from_sender_pool(pool, top_tx)

    def _sync_sender_status(self, pool: _SenderTxPool) -> None:
        if pool.has_valid_status:
            return

        old_status = pool.status
        if old_status == pool.Status.Suspended:
            self._suspended_sender_set.remove(pool.sender)
        elif old_status == pool.Status.Queued:
            self._sender_pool_queue.pop(pool)

        new_status = pool.sync_status()
        if new_status == pool.Status.Empty:
            self._sender_pool_dict.pop(pool.sender)
            self._sender_pool_heartbeat_queue.pop(pool)
            self._sol_sender_pool_dict.pop(pool.sol_address, None)
            # _LOG.debug(log_msg("done sender {Sender}", Sender=pool))
        elif new_status == pool.Status.Suspended:
            self._suspended_sender_set.add(pool.sender)
            self._tx_dict.dequeue_tx(pool.sender, pool.top_tx.nonce)
            # _LOG.debug(log_msg("suspend sender {Sender} with {TxCnt} txs, tx counter {StateTxCnt}", **pool.info()))
        elif new_status == pool.Status.Queued:
            self._sender_pool_queue.add(pool)
            self._tx_dict.queue_tx(pool.sender, pool.top_tx.nonce)
            # _LOG.debug(log_msg("resume sender {Sender} with {TxCnt} txs, tx counter {StateTxCnt}", **pool.info()))

    def _done_tx(self, tx: MpTxModel, state_tx_cnt: int, balance: int) -> None:
        if not (pool := self._find_sender_pool(tx.sender)):
            # _LOG.debug("not found! %s", tx.sender)
            return

        pool.done_tx(tx)
        self._tx_dict.done_tx(tx)

        self._schedule_sender_pool(pool, state_tx_cnt, balance)
        # _LOG.debug(log_msg("mempool {ChainID} has {TxCnt}({PendingTxCnt}) txs", **self._info()))

    def _check_oversized_and_reduce(self) -> None:
        tx_cnt_to_remove: Final[int] = self.tx_cnt - self._capacity - 1  # +1 for new tx, see add_tx()
        if tx_cnt_to_remove <= 0:
            return

        msg = log_msg(
            "clear {TxCntToRemove} txs from mempool {ChainID} with {TxCnt}({PendingTxCnt}) txs by lower gas price",
            TxCntToRemove=tx_cnt_to_remove,
            **self._info(),
        )
        _LOG.debug(msg)

        changed_pool_set: set[_SenderTxPool] = set()
        for i in range(tx_cnt_to_remove):
            # processing txs are absent in both queues,
            #   so it impossible to get the processing tx here
            if not (tx := self._tx_dict.peek_lower_tx()):
                break

            with logging_context(old_tx=tx.tx_id):
                pool = self._get_sender_pool(tx.sender)
                _LOG.debug(log_msg("remove tx {Tx} from {Sender} pool by lower gas price", Tx=tx, Sender=pool))
                changed_pool_set.add(pool)
                self._drop_tx_from_sender_pool(pool, tx)

        for pool in changed_pool_set:
            old_status = pool.status
            self._sync_sender_status(pool)
            self._sub_update_sender(pool, old_status)

        msg = log_msg(
            "done clearing mempool {ChainID}, {TxCnt}({PendingTxCnt}) txs left",
            **self._info(),
        )
        _LOG.debug(msg)

    def _sub_update_sender(self, pool: _SenderTxPool, old_status: _SenderTxPool.Status) -> None:
        new_status = pool.status
        if (old_status != new_status) and (pool.Status.Suspended in (old_status, new_status)):
            self._sub_sender_set.add(pool)

    async def _update_state_tx_cnt_loop(self) -> None:
        sleep_sec: Final[float] = ONE_BLOCK_SEC
        stop_task = asyncio.create_task(self._stop_event.wait())
        while not self._stop_event.is_set():
            try:
                await self._update_state_tx_cnt()
            except BaseException as exc:
                _LOG.error("error on updating state tx counters", exc_info=exc)

            await asyncio.wait({stop_task}, timeout=sleep_sec)

    async def _update_state_tx_cnt(self) -> None:
        if (not self._sub_sender_set) and self._watch_session.is_empty:
            return

        pool_list, self._sub_sender_set = tuple(self._sub_sender_set), set()
        await self._update_sol_addr_list(pool_list)

        for pool in pool_list:
            if pool.sender in self._suspended_sender_set:
                await self._watch_session.subscribe_account(pool.sol_address)
            else:
                await self._watch_session.unsubscribe_account(pool.sol_address)

        await self._watch_session.update()
        if not (key_list := self._watch_session.pop_changed_key_list()):
            return

        # fmt: off
        addr_list = tuple([
            NeonAddress.from_raw(pool.sender, self._chain_id)
            for key in key_list
            if (pool := self._sol_sender_pool_dict.get(key, None))
        ])
        # fmt: on
        acct_list = await self._core_api_client.get_neon_account_list(addr_list, None)

        for a in acct_list:
            if p := self._find_sender_pool(a.eth_address):
                if p.status == p.Status.Suspended:
                    if (p.state_tx_cnt, p.balance) != (a.state_tx_cnt, a.balance):
                        self._schedule_sender_pool(p, a.state_tx_cnt, a.balance)
                if p.status == p.Status.Suspended:
                    continue

            await self._watch_session.unsubscribe_account(a.sol_address)

    async def _update_sol_addr_list(self, pool_list: Sequence[_SenderTxPool]) -> None:
        if not (pool_list := tuple([x for x in pool_list if x.sol_address.is_empty])):
            return

        addr_list = tuple(map(lambda x: NeonAddress.from_raw(x.sender, self._chain_id), pool_list))
        acct_list = await self._core_api_client.get_neon_account_list(addr_list, None)
        for pool, acct in zip(pool_list, acct_list):
            if pool.sender not in self._sender_pool_dict:
                continue
            else:
                pool.set_sol_address(acct.sol_address)
                self._sol_sender_pool_dict[acct.sol_address] = pool

    async def _heartbeat_loop(self) -> None:
        sleep_sec: Final[float] = self._eviction_timeout_sec / 10
        stop_task = asyncio.create_task(self._stop_event.wait())
        with logging_context(ctx="mp-heartbeat-clear-txs"):
            while not self._stop_event.is_set():
                try:
                    self._check_heartbeat_and_drop(self._eviction_timeout_sec)
                except BaseException as exc:
                    _LOG.error("error on clearing by heartbeat", exc_info=exc)

                await asyncio.wait({stop_task}, timeout=sleep_sec)

    def _check_heartbeat_and_drop(self, eviction_timeout_sec: int) -> None:
        threshold: Final[int] = int(time.monotonic()) - eviction_timeout_sec
        msg = log_msg(
            "clear mempool {ChainID} with {TxCnt}({PendingTxCnt} txs by heartbeat below {Threshold} sec",
            Threshold=threshold,
            **self._info(),
        )
        _LOG.debug(msg)

        while not self._sender_pool_heartbeat_queue.is_empty:
            pool = self._sender_pool_heartbeat_queue[self._top_index]
            if threshold < pool.heartbeat_sec or pool.is_processing:
                break

            msg = log_msg(
                "dropping pool {Sender} with {TxCnt} txs, heartbeat {Heartbeat} sec",
                Sender=pool,
                TxCnt=pool.tx_cnt,
                Heartbeat=pool.heartbeat_sec,
            )
            _LOG.debug(msg)

            tx_list = pool.pop_tx_list()
            for tx in tx_list:
                _LOG.debug(log_msg("drop tx {Tx} by heartbeat", Tx=tx))

            self._tx_dict.pop_tx_list(tx_list)
            self._sync_sender_status(pool)

        msg = log_msg(
            "done clearing mempool {ChainID}, {TxCnt}({PendingTxCnt}) txs left",
            **self._info(),
        )
        _LOG.debug(msg)

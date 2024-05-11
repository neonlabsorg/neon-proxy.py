from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import time
from typing import Final, Sequence

from common.config.config import Config
from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.client import CoreApiClient
from common.utils.cached import cached_method, reset_cached_method
from common.utils.json_logger import logging_context, log_msg
from .sender_nonce import SenderNonce
from .sorted_queue import SortedQueue
from ..base.mp_api import MpTxModel, MpTxRespCode, MpTxResp, MpTxPoolContentResp

_LOG = logging.getLogger(__name__)


class _TxDict:
    _top_index = -1

    def __init__(self, chain_id: int) -> None:
        self._chain_id = chain_id
        self._tx_dict: dict[SenderNonce, MpTxModel] = {}
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

        return self._tx_dict.pop(sender_nonce)

    def pop_tx_list(self, tx_list: Sequence[MpTxModel]) -> None:
        for tx in tx_list:
            old_tx = self._tx_dict.pop(SenderNonce.from_raw(tx), None)
            assert old_tx, f"Tx {tx} is absent in dictionary"

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

    class State(enum.IntEnum):
        Empty = 1
        Suspended = 2
        Queued = 3
        Processing = 4

    def __init__(self, sender: EthAddress, chain_id: int) -> None:
        self._state = self.State.Empty
        self._sender: Final[EthAddress] = sender
        self._chain_id: Final[int] = chain_id
        self._gas_price = 0
        self._heartbeat_sec = int(time.monotonic())
        self._state_tx_cnt = 0
        self._processing_tx: MpTxModel | None = None
        self._tx_nonce_queue = SortedQueue[MpTxModel, int, str](
            lt_key_func=lambda a: -a.nonce,
            eq_key_func=lambda a: a.neon_tx_hash,
        )

    @cached_method
    def to_string(self) -> str:
        return f"{self._sender.to_string()}:0x{self._chain_id:x}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def __hash__(self) -> int:
        return hash(self._sender)

    @property
    def sender(self) -> EthAddress:
        return self._sender

    @property
    def gas_price(self) -> int:
        return self._gas_price

    @property
    def state(self) -> _SenderTxPool.State:
        return self._state

    def sync_state(self) -> _SenderTxPool.State:
        self._state = self._actual_state
        top_tx = self.top_tx
        self._gas_price = top_tx.gas_price if top_tx else 0
        self._get_pending_tx_cnt.reset_cache(self)
        return self._state

    @property
    def has_valid_state(self) -> bool:
        return self._actual_state == self._state

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
        _LOG.debug(self._log_action("add tx", tx))

    @property
    def top_tx(self) -> MpTxModel | None:
        return self._tx_nonce_queue[self._top_index] if not self.is_empty else None

    def acquire_tx(self, tx: MpTxModel) -> MpTxModel:
        assert not self.is_processing
        assert tx.neon_tx_hash == self.top_tx.neon_tx_hash

        self._processing_tx = self.top_tx
        self._state = self.State.Processing
        return self._processing_tx

    @property
    def pending_tx_cnt(self) -> int | None:
        return self._get_pending_tx_cnt()

    @reset_cached_method
    def _get_pending_tx_cnt(self) -> int | None:
        if self.state in (self.State.Suspended, self.State.Empty):
            # _LOG.debug("state = %s", self.state)
            return None

        pending_tx_cnt = self._state_tx_cnt
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
    def last_nonce(self) -> int | None:
        return self._tx_nonce_queue[self._bottom_index].nonce if not self.is_empty else None

    @property
    def state_tx_cnt(self) -> int:
        if self.is_processing:
            assert self._state_tx_cnt == self._processing_tx.nonce
            return self._processing_tx.nonce + 1
        return self._state_tx_cnt

    def set_state_tx_cnt(self, value: int) -> None:
        if not self.is_processing:
            self._state_tx_cnt = value

    @property
    def heartbeat_sec(self) -> int:
        return self._heartbeat_sec

    def done_tx(self, tx: MpTxModel) -> None:
        self._validate_processing_tx(tx)

        self._tx_nonce_queue.pop(self._top_index)
        self._processing_tx = None
        _LOG.debug(self._log_action("done tx", tx))

    def drop_tx(self, tx: MpTxModel) -> None:
        assert (
            not self.is_processing or tx.neon_tx_hash != self._processing_tx.neon_tx_hash
        ), f"cannot drop processing tx {tx.neon_tx_hash}"

        self._tx_nonce_queue.pop(tx)
        _LOG.debug(self._log_action("drop tx", tx))

    def cancel_process_tx(self, tx: MpTxModel) -> None:
        self._validate_processing_tx(tx)
        self._processing_tx = None

    @property
    def pending_stop_pos(self) -> int:
        if self.state in (self.State.Suspended, self.State.Empty):
            return 0

        pending_pos, pending_nonce = 0, self._state_tx_cnt
        for tx in reversed(self._tx_nonce_queue):
            if tx.nonce != pending_nonce:
                break
            pending_nonce += 1
            pending_pos += 1
        return pending_pos

    def tx_list(self) -> list[MpTxModel]:
        return list(reversed(self._tx_nonce_queue))

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
    def _actual_state(self) -> _SenderTxPool.State:
        if self.is_empty:
            return self.State.Empty
        elif self.is_processing:
            return self.State.Processing
        elif self._state_tx_cnt != self.top_tx.nonce:
            return self.State.Suspended
        return self.State.Queued

    def _log_action(self, msg: str, tx: MpTxModel) -> dict:
        return log_msg(
            f"{msg} " "{Tx}, {Sender} pool has {TxCnt} txs, tx counter {StateTxCnt}, next tx {NextTx}",
            Tx=tx,
            **self.info(),
        )


class MpTxSchedule:
    _top_index: Final[int] = -1

    def __init__(self, cfg: Config, core_api_client: CoreApiClient, chain_id: int) -> None:
        self._core_api_client = core_api_client
        self._capacity: Final[int] = cfg.mp_capacity
        self._capacity_high_watermark: Final[int] = int(self._capacity * cfg.mp_capacity_high_watermark)
        self._eviction_timeout_sec = cfg.mp_eviction_timeout_sec

        self._tx_dict = _TxDict(chain_id)
        self._chain_id: Final[int] = chain_id

        self._sender_pool_dict: dict[EthAddress, _SenderTxPool] = dict()
        self._sender_pool_heartbeat_queue = SortedQueue[_SenderTxPool, int, str](
            lt_key_func=lambda a: -a.heartbeat_sec,
            eq_key_func=lambda a: a.sender,
        )
        self._sender_pool_queue = SortedQueue[_SenderTxPool, int, str](
            lt_key_func=lambda a: a.gas_price,
            eq_key_func=lambda a: a.sender,
        )
        self._suspended_sender_set: set[EthAddress] = set()

        self._stop_event = asyncio.Event()
        self._heartbeat_task: asyncio.Task | None = None
        self._update_state_cnt_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._update_state_cnt_task = asyncio.create_task(self._update_state_tx_cnt_loop())

    async def stop(self) -> None:
        self._stop_event.set()

        if self._heartbeat_task:
            await self._heartbeat_task

        if self._update_state_cnt_task:
            await self._update_state_cnt_task

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

    def add_tx(self, tx: MpTxModel, state_tx_cnt: int) -> MpTxResp:
        _LOG.debug(log_msg("add tx {Tx} to mempool {ChainID} with {TxCnt}({PendingTxCnt}) txs", Tx=tx, **self._info()))

        old_tx = self._tx_dict.get_tx(tx.sender, tx.nonce)
        if old_tx:
            if old_tx.neon_tx_hash == tx.neon_tx_hash:
                _LOG.debug(log_msg("tx {Tx} is already scheduled", Tx=tx))
                return MpTxResp(code=MpTxRespCode.AlreadyKnown, state_tx_cnt=None)
            elif old_tx.gas_price >= tx.gas_price:
                _LOG.debug(
                    log_msg("old tx {OldTx} has higher gas-price than {GasPrice}", OldTx=old_tx, GasPrice=tx.gas_price)
                )
                return MpTxResp(code=MpTxRespCode.Underprice, state_tx_cnt=None)

        pool = self._get_or_create_sender_pool(tx.sender)

        # pool.state_tx_cnt returns (state_tx_cnt +  1), if it has a processing tx
        state_tx_cnt = max(state_tx_cnt, pool.state_tx_cnt)

        if self.tx_cnt >= self._capacity_high_watermark:
            gapped_tx = self._tx_dict.peek_gapped_lower_tx()
            if _is_new_tx_gapped := (pool.pending_tx_cnt or state_tx_cnt) < tx.nonce:
                if not gapped_tx:
                    return MpTxResp(code=MpTxRespCode.NonceTooHigh, state_tx_cnt=state_tx_cnt)
                elif tx.gas_price < gapped_tx.gas_price:
                    _LOG.debug(
                        log_msg(
                            "lowermost gapped tx {LowerTx} has higher gas-price than {GasPrice}",
                            LowerTx=gapped_tx,
                            GasPrice=tx.gas_price,
                        )
                    )
                    return MpTxResp(code=MpTxRespCode.Underprice, state_tx_cnt=None)
            elif (self.tx_cnt >= self._capacity) and (not gapped_tx):
                pending_tx = self._tx_dict.peek_pending_lower_tx()
                if pending_tx and (tx.gas_price < pending_tx.gas_price):
                    _LOG.debug(
                        log_msg(
                            "lowermost pending tx {LowerTx} has higher gas-price than {GasPrice}",
                            LowerTx=pending_tx,
                            GasPrice=tx.gas_price,
                        )
                    )
                    return MpTxResp(code=MpTxRespCode.Underprice, state_tx_cnt=None)

        if pool.is_processing:
            top_tx = pool.top_tx
            if top_tx.nonce == tx.nonce:
                _LOG.debug(log_msg("tx {OldTx} is processing", OldTx=top_tx))
                return MpTxResp(code=MpTxRespCode.NonceTooLow, state_tx_cnt=top_tx.nonce + 1)

        if state_tx_cnt > tx.nonce:
            _LOG.debug(
                log_msg(
                    "sender {Sender} has higher tx counter {StateTxCnt} > {Nonce}",
                    Sender=pool,
                    StateTxCnt=hex(state_tx_cnt),
                    Nonce=hex(tx.nonce),
                )
            )
            return MpTxResp(code=MpTxRespCode.NonceTooLow, state_tx_cnt=state_tx_cnt)

        # Everything is ok, let's add transaction to the pool
        if old_tx:
            with logging_context(tx=old_tx.tx_id):
                _LOG.debug(log_msg("replace tx {OldTx} with tx {Tx}", OldTx=old_tx, Tx=tx))
                self._drop_tx_from_sender_pool(pool, old_tx)

        self._check_oversized_and_reduce()
        self._add_tx_to_sender_pool(pool, tx)
        self._schedule_sender_pool(pool, state_tx_cnt)
        _LOG.debug(
            log_msg("done add tx {Tx}, mempool {ChainID} has {TxCnt}({PendingTxCnt}) txs", Tx=tx, **self._info())
        )
        return MpTxResp(code=MpTxRespCode.Success, state_tx_cnt=None)

    def drop_tx(self, sender: EthAddress, nonce: int) -> bool:
        if not (tx := self._tx_dict.get_tx(sender, nonce)):
            return True

        pool = self._get_sender_pool(tx.sender)
        if pool.is_processing:
            _LOG.debug(log_msg("cannot drop processing tx {Tx}", Tx=tx))
            return False

        self._drop_tx_from_sender_pool(pool, tx)
        self._schedule_sender_pool(pool, tx.nonce)
        return True

    @property
    def tx_cnt(self) -> int:
        return len(self._tx_dict)

    @property
    def pending_tx_cnt(self) -> int:
        return self._tx_dict.len_tx_gas_price_queue

    def peek_top_tx(self) -> MpTxModel | None:
        if not self._sender_pool_queue:
            return None
        return self._sender_pool_queue[self._top_index].top_tx

    def acquire_tx(self, tx: MpTxModel) -> None:
        pool = self._get_sender_pool(tx.sender)
        assert pool.state == pool.State.Queued

        self._sender_pool_queue.pop(pool)
        pool.acquire_tx(tx)
        self._tx_dict.acquire_tx(tx)

    def get_pending_tx_cnt(self, sender: EthAddress) -> int | None:
        pool = self._find_sender_pool(sender)
        return None if not pool else pool.pending_tx_cnt

    def get_last_tx_cnt(self, sender: EthAddress) -> int | None:
        pool = self._find_sender_pool(sender)
        return None if not pool else pool.last_nonce + 1

    def done_tx(self, tx: MpTxModel, state_tx_cnt: int) -> None:
        _LOG.debug(log_msg("done tx {Tx}", Tx=tx))
        self._done_tx(tx, state_tx_cnt)

    def fail_tx(self, tx: MpTxModel, state_tx_cnt: int) -> None:
        _LOG.debug(log_msg("fail tx {Tx}", Tx=tx))
        self._done_tx(tx, state_tx_cnt)

    def cancel_tx(self, tx: MpTxModel, state_tx_cnt: int) -> bool:
        _LOG.debug(log_msg("cancel tx {Tx}", Tx=tx))
        pool = self._get_sender_pool(tx.sender)
        pool.cancel_process_tx(tx)
        self._tx_dict.cancel_process_tx(tx)

        self._schedule_sender_pool(pool, state_tx_cnt)
        return True

    def get_content(self) -> MpTxPoolContentResp:
        pending_list: list[NeonTxModel] = list()
        queued_list: list[NeonTxModel] = list()

        for tx_pool in self._sender_pool_dict.values():
            tx_list = list(map(lambda tx: tx.neon_tx, tx_pool.tx_list()))
            pending_stop_pos = tx_pool.pending_stop_pos
            pending_list.extend(tx_list[:pending_stop_pos])
            queued_list.extend(tx_list[pending_stop_pos:])

        return MpTxPoolContentResp(pending_list=tuple(pending_list), queued_list=tuple(queued_list))

    # protected:

    def _info(self) -> dict:
        return dict(
            ChainID=hex(self._chain_id),
            TxCnt=self.tx_cnt,
            PendingTxCnt=self.pending_tx_cnt,
        )

    def _add_tx_to_sender_pool(self, pool: _SenderTxPool, tx: MpTxModel) -> None:
        if not (is_new_pool := pool.is_empty):
            self._sender_pool_heartbeat_queue.pop(pool)

        is_gapped_tx = (pool.state in (pool.State.Suspended, pool.state.Empty)) or (pool.pending_tx_cnt < tx.nonce)
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
            _LOG.debug(log_msg("find pool {Sender} with {TxCnt} txs", Sender=pool, TxCnt=pool.tx_cnt))
        else:
            pool = _SenderTxPool(sender, self._chain_id)
            _LOG.debug(log_msg("create new pool {Sender}", Sender=pool))
        return pool

    def _get_sender_pool(self, sender: EthAddress) -> _SenderTxPool:
        pool = self._find_sender_pool(sender)
        assert pool, f"Failed to get sender tx pool by sender {sender}"
        return pool

    def _schedule_sender_pool(self, pool: _SenderTxPool, state_tx_cnt: int) -> None:
        self._drop_old_tx_list(pool, state_tx_cnt)
        self._sync_sender_state(pool)
        pool.set_state_tx_cnt(state_tx_cnt)
        self._sync_sender_state(pool)

    def _drop_old_tx_list(self, pool: _SenderTxPool, state_tx_cnt: int) -> None:
        if pool.state_tx_cnt == state_tx_cnt:
            return
        elif pool.is_processing:
            return

        while top_tx := pool.top_tx:
            if top_tx.nonce >= state_tx_cnt:
                break
            self._drop_tx_from_sender_pool(pool, top_tx)

    def _sync_sender_state(self, pool: _SenderTxPool) -> None:
        if pool.has_valid_state:
            return

        old_state = pool.state
        if old_state == pool.State.Suspended:
            self._suspended_sender_set.remove(pool.sender)
        elif old_state == pool.State.Queued:
            self._sender_pool_queue.pop(pool)

        new_state = pool.sync_state()
        if new_state == pool.State.Empty:
            self._sender_pool_dict.pop(pool.sender)
            self._sender_pool_heartbeat_queue.pop(pool)
            _LOG.debug(log_msg("done sender {Sender}", Sender=pool))
        elif new_state == pool.State.Suspended:
            self._suspended_sender_set.add(pool.sender)
            self._tx_dict.dequeue_tx(pool.sender, pool.top_tx.nonce)
            _LOG.debug(log_msg("suspend sender {Sender} with {TxCnt} txs, tx counter {StateTxCnt}", **pool.info()))
        elif new_state == pool.State.Queued:
            self._sender_pool_queue.add(pool)
            self._tx_dict.queue_tx(pool.sender, pool.top_tx.nonce)
            _LOG.debug(log_msg("resume sender {Sender} with {TxCnt} txs, tx counter {StateTxCnt}", **pool.info()))

    def _done_tx(self, tx: MpTxModel, state_tx_cnt: int) -> None:
        pool = self._get_sender_pool(tx.sender)
        pool.done_tx(tx)
        self._tx_dict.done_tx(tx)

        self._schedule_sender_pool(pool, state_tx_cnt)
        _LOG.debug(log_msg("mempool {ChainID} has {TxCnt}({PendingTxCnt}) txs", **self._info()))

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
            self._sync_sender_state(pool)

        msg = log_msg(
            "done clearing mempool {ChainID}, {TxCnt}({PendingTxCnt}) txs left",
            **self._info(),
        )
        _LOG.debug(msg)

    async def _update_state_tx_cnt_loop(self) -> None:
        sleep_sec: Final[float] = ONE_BLOCK_SEC * 3
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
            if self._stop_event.is_set():
                break

            try:
                await self._update_state_tx_cnt()
            except BaseException as exc:
                _LOG.error("error on updating state tx counters", exc_info=exc)

    async def _update_state_tx_cnt(self) -> None:
        if not self._suspended_sender_set:
            return

        addr_list = tuple(map(lambda addr: NeonAccount.from_raw(addr, self._chain_id), self._suspended_sender_set))
        acct_list = await self._core_api_client.get_neon_account_list(addr_list, None)

        for acct in acct_list:
            pool = self._find_sender_pool(acct.account.eth_address)
            if pool and pool.state == pool.State.Suspended:
                self._schedule_sender_pool(pool, acct.state_tx_cnt)

    async def _heartbeat_loop(self) -> None:
        sleep_sec: Final[float] = self._eviction_timeout_sec / 10
        with logging_context(ctx="mp-heartbeat-clear-txs"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    self._check_heartbeat_and_drop(self._eviction_timeout_sec)
                except BaseException as exc:
                    _LOG.error("error on clearing by heartbeat", exc_info=exc)

    def _check_heartbeat_and_drop(self, eviction_timeout_sec: int) -> None:
        threshold: Final[int] = int(time.time()) - eviction_timeout_sec
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

            self._tx_dict.pop_tx_list(pool.pop_tx_list())
            self._sync_sender_state(pool)

        msg = log_msg(
            "done clearing mempool {ChainID}, {TxCnt}({PendingTxCnt}) txs left",
            **self._info(),
        )
        _LOG.debug(msg)

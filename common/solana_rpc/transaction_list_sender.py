from __future__ import annotations

import abc
import asyncio
import dataclasses
import enum
import logging
import random
import time
from typing import Sequence, Final

from .client import SolClient
from .errors import (
    SolUnknownReceiptError,
    SolBlockhashNotFound,
    SolCbExceededError,
    SolNoMoreRetriesError,
    SolWritableError,
)
from .transaction_error_parser import SolTxErrorParser
from .transaction_list_sender_stat import SolTxStatClient, SolTxDoneData, SolTxFailData
from .ws_client import SolWatchTxSession
from ..config.config import Config
from ..config.constants import ONE_BLOCK_SEC
from ..solana.commit_level import SolCommit
from ..solana.errors import SolAltError
from ..solana.hash import SolBlockHash
from ..solana.signature import SolTxSig
from ..solana.transaction import SolTx
from ..solana.transaction_meta import SolRpcTxSlotInfo, SolRpcTxReceiptInfo

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SolTxSendState:
    class Status(enum.Enum):
        WaitForReceipt = enum.auto()
        GoodReceipt = enum.auto()
        ResubmitReceipt = enum.auto()
        ErrorReceipt = enum.auto()

    status: Status
    tx: SolTx
    receipt: SolRpcTxReceiptInfo | None
    error: BaseException | None

    @property
    def name(self) -> str:
        return self.tx.name

    @property
    def slot(self) -> int | None:
        return self.receipt.slot if isinstance(self.receipt, SolRpcTxSlotInfo) else None


class SolTxListSigner(abc.ABC):
    @abc.abstractmethod
    async def sign_tx_list(self, sol_tx_list: Sequence[SolTx]) -> Sequence[SolTx]: ...


class SolTxListSender:
    _wait_sec: Final[float] = ONE_BLOCK_SEC / 2

    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        sol_tx_signer: SolTxListSigner,
        stat_client: SolTxStatClient,
    ) -> None:
        self._cfg = cfg
        self._stat_client = stat_client
        self._sol_client = sol_client
        self._tx_signer = sol_tx_signer
        self._num_slots_behind: int | None

        self._blockhash: SolBlockHash | None = None
        self._valid_block_height = 0

        self._max_retry_cnt = int(cfg.commit_timeout_sec // ONE_BLOCK_SEC)
        self._bad_blockhash_set: set[SolBlockHash] = set()
        self._tx_list: list[SolTx] = list()
        self._tx_state_dict: dict[SolTxSig, SolTxSendState] = dict()
        self._tx_state_list_dict: dict[SolTxSendState.Status, list[SolTxSendState]] = dict()
        self._tx_time_dict: dict[SolTxSig, int] = dict()

    async def send(self, tx_list: Sequence[SolTx]) -> bool:
        assert not self._tx_list
        if not tx_list:
            return False

        self._tx_list = list(tx_list)

        # save tx start time
        now = time.monotonic_ns()
        for tx in self._tx_list:
            if tx.is_signed:
                self._tx_time_dict[tx.sig] = now

        return await self._send()

    async def recheck(self, tx_list: Sequence[SolTx]) -> bool:
        assert not self._tx_list
        if not tx_list:
            return False
        # _LOG.debug("recheck txs: %s", tx_list)

        # The Sender should check all (failed too) txs again, because the state may have changed
        tx_sig_list = tuple(map(lambda tx: tx.sig, tx_list))
        await self._get_tx_receipt_list(tx_sig_list, tx_list)

        self._get_tx_list_for_send()
        return await self._send()

    def clear(self) -> None:
        self._blockhash = None
        self._tx_list.clear()
        self._tx_state_dict.clear()
        self._tx_state_list_dict.clear()

    def _is_done(self) -> bool:
        """Function can be overloaded to define the custom logic to stop tx sending"""
        _ = self
        return False

    async def _send(self) -> bool:
        for retry_idx in range(self._cfg.retry_on_fail):
            if not self._tx_list:
                if not await self._is_completed_commit_level():
                    # all txs were sent, but the commit statuses aren't enough to confirm txs on the network
                    #  let's sleep for some time
                    await asyncio.sleep(self._wait_sec)
                    #  refresh all tx receipts from the network
                    await self._refresh_tx_receipt_list()
                    #  revalidate txs and get not-confirmed txs for sending
                    self._get_tx_list_for_send()
                    continue
                else:
                    return True

            if self._is_done():
                return True

            await self._sign_tx_list()
            if self._cfg.fuzz_fail_pct:
                await self._fuzz_send_tx_list()
            else:
                await self._send_tx_list()
            _LOG.debug("retry %s sending stat: %s", retry_idx, self._FmtStat(self))

            # get txs with preflight check errors for resubmitting
            self._get_tx_list_for_send()
            if self._tx_list:
                # sleep for some time to drop conditions for the error
                await asyncio.sleep(self._wait_sec)
                continue

            # get receipts from the network
            await self._wait_for_tx_receipt_list()
            _LOG.debug("retry %s waiting stat: %s", retry_idx, self._FmtStat(self))

            # at this point the Sender has all receipts from the network;
            #  some txs (blockhash errors, for example) can require the resending
            self._get_tx_list_for_send()

        raise SolNoMoreRetriesError()

    async def _is_completed_commit_level(self) -> bool:
        """
        Find the maximum block slot in the receipt list
        and check the commitment level of the block.
        """
        commit_level = self._cfg.commit_type.to_level()
        if SolCommit.Confirmed.to_level() >= commit_level:
            return True

        # find maximum block slot
        max_slot = max([tx_state.slot for tx_state in self._tx_state_dict.values() if tx_state.slot] or [0])
        if not max_slot:
            # _LOG.debug("tx list does not contain a block - skip validating of the commit level")
            return True

        max_block_status = await self._sol_client.get_block_status(max_slot)
        return max_block_status.commit.to_level() >= commit_level

    class _FmtStat:
        def __init__(self, sender: SolTxListSender) -> None:
            self._sender = sender

        def to_string(self) -> str:
            status_list = [
                f"{tx_status.name} {len(self._sender._tx_state_list_dict[tx_status])}"
                for tx_status in list(SolTxSendState.Status)
                if tx_status in self._sender._tx_state_list_dict
            ]
            return ", ".join(status_list)

        def __repr__(self) -> str:
            return self.to_string()

    async def _get_fuzz_blockhash(self) -> SolBlockHash:
        base_slot = await self._sol_client.get_recent_slot()
        slot = max(base_slot - random.randint(525, 1025), 2)
        blockhash = await self._sol_client.get_blockhash(slot)
        _LOG.debug("fuzzing blockhash: %s", blockhash)
        return blockhash

    async def _get_blockhash(self) -> SolBlockHash:
        if self._blockhash in self._bad_blockhash_set:
            self._blockhash = None

        if self._blockhash:
            block_height = await self._sol_client.get_block_height()
            if block_height > self._valid_block_height:
                self._bad_blockhash_set.add(self._blockhash)
                self._blockhash = None

        if self._blockhash:
            return self._blockhash

        blockhash, valid_block_height = await self._sol_client.get_recent_blockhash(SolCommit.Finalized)
        if blockhash in self._bad_blockhash_set:
            raise SolBlockhashNotFound()

        self._blockhash = blockhash
        # decrease the available block height to remove edge conditions
        self._valid_block_height = valid_block_height - 10
        return self._blockhash

    async def _sign_tx_list(self) -> None:
        fuzz_fail_pct = self._cfg.fuzz_fail_pct
        blockhash = await self._get_blockhash()
        now = time.monotonic_ns()
        signed_tx_list: list[SolTx] = list()
        not_signed_tx_list: list[SolTx] = list()

        for tx in self._tx_list:
            if tx.is_signed:
                self._commit_tx_stat_time(tx, now, is_fail=True)
                self._tx_state_dict.pop(tx.sig, None)
                if tx.recent_blockhash in self._bad_blockhash_set:
                    # _LOG.debug("flash bad blockhash: %s for tx %s", tx.recent_blockhash, tx)
                    tx.set_recent_blockhash(None)

            if tx.is_signed:
                # _LOG.debug("skip signing for %s", tx)
                signed_tx_list.append(tx)
                continue

            # Fuzz testing of bad blockhash
            if fuzz_fail_pct > 0 and (random.randint(1, 100) <= fuzz_fail_pct):
                tx.set_recent_blockhash(await self._get_fuzz_blockhash())
            # <- Fuzz testing
            else:
                tx.set_recent_blockhash(blockhash)
            not_signed_tx_list.append(tx)

        self._tx_list = signed_tx_list
        if not not_signed_tx_list:
            return

        new_signed_tx_list = await self._tx_signer.sign_tx_list(not_signed_tx_list)
        self._tx_list.extend(new_signed_tx_list)

        # save tx time
        now = time.monotonic_ns()
        for tx in new_signed_tx_list:
            self._tx_time_dict[tx.sig] = now

    async def _send_tx_list(self) -> None:
        if not (tx_list := self._tx_list):
            return
        max_retry_cnt = self._max_retry_cnt

        _LOG.debug("send transactions: %s", self._FmtTxNameStat(tx_list))
        tx_sig_list = await self._sol_client.send_tx_list(tx_list, skip_preflight=False, max_retry_cnt=max_retry_cnt)

        tx_receipt_list = list(map(lambda x: x if not isinstance(x, SolTxSig) else None, tx_sig_list))
        await self._add_tx_receipt_list(self._tx_list, tx_receipt_list, SolTxSendState.Status.WaitForReceipt)

    async def _fuzz_send_tx_list(self) -> None:
        fuzz_fail_pct = self._cfg.fuzz_fail_pct

        # Fuzz testing of skipping of txs by Solana node
        if self._tx_list:
            skip_flag_list = [random.randint(1, 100) <= fuzz_fail_pct for _ in self._tx_list]
            skip_tx_list = [tx for tx, skip_flag in zip(self._tx_list, skip_flag_list) if skip_flag]
            self._tx_list = [tx for tx, skip_flag in zip(self._tx_list, skip_flag_list) if not skip_flag]

            skip_tx_receipt_list = [None] * len(skip_tx_list)
            await self._add_tx_receipt_list(skip_tx_list, skip_tx_receipt_list, SolTxSendState.Status.WaitForReceipt)
        # <- Fuzz testing

        await self._send_tx_list()

    class _FmtTxNameStat:
        def __init__(self, tx_list: Sequence[SolTx]) -> None:
            self._tx_list = tx_list

        def to_string(self) -> str:
            tx_name_dict: dict[str, int] = dict()
            for tx in self._tx_list:
                tx_name = tx.name or "Unknown"
                tx_name_dict[tx_name] = tx_name_dict.get(tx_name, 0) + 1

            return " + ".join(f"{name}({cnt})" for name, cnt in tx_name_dict.items())

        def __repr__(self) -> str:
            return self.to_string()

    def _get_tx_list_for_send(self) -> None:
        self._tx_list.clear()

        if self._is_done():
            return

        # Raise error if
        if tx_state_list := self._tx_state_list_dict.pop(SolTxSendState.Status.ErrorReceipt, None):
            raise tx_state_list[0].error

        # Resend txs with the resubmitted status
        if tx_state_list := self._tx_state_list_dict.pop(SolTxSendState.Status.ResubmitReceipt, None):
            self._tx_list.extend(map(lambda x: x.tx, tx_state_list))

    async def _refresh_tx_receipt_list(self) -> None:
        tx_list = tuple(map(lambda tx_state: tx_state.tx, self._tx_state_dict.values()))
        tx_sig_list = tuple(map(lambda tx: tx.sig, tx_list))
        await self._get_tx_receipt_list(tx_sig_list, tx_list)

    async def _wait_for_tx_receipt_list(self) -> None:
        if not (tx_state_list := self._tx_state_list_dict.pop(SolTxSendState.Status.WaitForReceipt, None)):
            # _LOG.debug("no new receipts, because the transaction list is empty")
            return

        tx_sig_list: list[SolTxSig] = list()
        tx_list: list[SolTx] = list()
        for tx_state in tx_state_list:
            tx_sig_list.append(tx_state.tx.sig)
            tx_list.append(tx_state.tx)

        async with SolWatchTxSession(self._cfg, self._sol_client) as watch_session:
            await watch_session.wait_for_tx_receipt_list(tx_list, SolCommit.Confirmed, self._cfg.commit_timeout_sec)
        await self._get_tx_receipt_list(tx_sig_list, tx_list)

    async def _get_tx_receipt_list(self, tx_sig_list: Sequence[SolTxSig], tx_list: Sequence[SolTx]) -> None:
        tx_receipt_list = await self._sol_client.get_tx_list(tx_sig_list, SolCommit.Confirmed)

        now = time.monotonic_ns()
        for tx, tx_receipt in zip(tx_list, tx_receipt_list):
            if tx_receipt:
                self._commit_tx_stat_time(tx, now, is_fail=False)

        await self._add_tx_receipt_list(tx_list, tx_receipt_list, SolTxSendState.Status.ResubmitReceipt)

    def _decode_tx_status(self, tx: SolTx, tx_receipt: SolRpcTxReceiptInfo) -> SolTxSendState:
        status = SolTxSendState.Status

        tx_status = status.GoodReceipt
        tx_error: BaseException | None = None
        tx_error_parser = SolTxErrorParser(tx, tx_receipt)

        if num_slots_behind := tx_error_parser.get_num_slots_behind():
            self._num_slots_behind = max(self._num_slots_behind, num_slots_behind)
            _LOG.debug("slots behind %s", self._num_slots_behind)
            tx_status = status.ResubmitReceipt
        elif tx_error_parser.check_if_blockhash_notfound():
            if tx.recent_blockhash not in self._bad_blockhash_set:
                _LOG.debug("bad blockhash: %s", tx.recent_blockhash)
                self._bad_blockhash_set.add(tx.recent_blockhash)
            tx_status = status.ResubmitReceipt
        elif tx_error_parser.check_if_alt_error():
            tx_status, tx_error = status.ErrorReceipt, SolAltError("Bad ALT on send tx")
        elif tx_error_parser.check_if_writable_error():
            tx_status, tx_error = status.ErrorReceipt, SolWritableError()
        elif tx_error_parser.check_if_cb_exceeded():
            # if cu_consumed := tx_error_parser.cu_consumed:
            #     _LOG.debug("CUs consumed: %s", cu_consumed)
            tx_status, tx_error = status.ErrorReceipt, SolCbExceededError(tx_error_parser.cu_consumed)
        elif data := tx_error_parser.get_error():
            if data.address.is_empty:
                _LOG.debug("unknown Solana receipt %s: %s", tx, tx_receipt)
            else:
                _LOG.debug("unknown Solana Program fail %s: %s - %s", tx, data.address, data.message)
            tx_status, tx_error = status.ErrorReceipt, SolUnknownReceiptError(data)

        return SolTxSendState(tx_status, tx, tx_receipt, tx_error)

    @classmethod
    def _empty_tx_status(cls, tx: SolTx, tx_status: SolTxSendState.Status) -> SolTxSendState:
        return SolTxSendState(tx_status, tx, None, None)

    async def _add_tx_receipt_list(
        self,
        tx_list: Sequence[SolTx],
        tx_receipt_list: Sequence[SolRpcTxReceiptInfo | None],
        empty_status: SolTxSendState.Status,
    ) -> None:
        self._num_slots_behind = 0
        for tx, tx_receipt in zip(tx_list, tx_receipt_list):
            tx_state = self._decode_tx_status(tx, tx_receipt) if tx_receipt else self._empty_tx_status(tx, empty_status)
            self._tx_state_dict[tx.sig] = tx_state
            self._tx_state_list_dict.setdefault(tx_state.status, list()).append(tx_state)

        if self._num_slots_behind:
            _LOG.warning("Solana node is behind %s slots from the cluster, sleep...", self._num_slots_behind)
            await asyncio.sleep(ONE_BLOCK_SEC)

    def _commit_tx_stat_time(self, tx: SolTx, now: int, is_fail: bool) -> None:
        if not tx.is_signed:
            return
        elif not (start_time_nsec := self._tx_time_dict.pop(tx.sig, None)):
            return

        process_time_nsec = now - start_time_nsec
        if is_fail:
            self._stat_client.commit_sol_tx_fail(SolTxFailData(time_nsec=process_time_nsec))
        else:
            self._stat_client.commit_sol_tx_done(SolTxDoneData(time_nsec=process_time_nsec))

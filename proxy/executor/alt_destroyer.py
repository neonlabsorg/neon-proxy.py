from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Final, Sequence

from common.config.constants import ONE_BLOCK_SEC, MIN_FINALIZE_SEC
from common.ethereum.hash import EthTxHash
from common.solana.alt_program import SolAltID, SolAltProg, SolAltIxCode
from common.solana.commit_level import SolCommit
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import SolNoMoreRetriesError
from common.solana_rpc.transaction_list_sender import SolTxListSender
from common.solana_rpc.ws_client import SolWatchTxSession
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context, log_msg
from .server_abc import ExecutorComponent
from .transaction_list_signer import OpTxListSigner
from ..base.ex_api import NeonAltModel

_LOG = logging.getLogger(__name__)


@dataclass
class _NeonAltInfo:
    sol_alt: SolAltID
    neon_tx_hash: EthTxHash
    next_check_sec: int
    attempt_cnt: int

    @cached_property
    def ctx_id(self) -> dict:
        tx = self.neon_tx_hash.to_bytes()[:4].hex()
        return dict(alt=self.sol_alt.ctx_id, tx=tx)

    @cached_property
    def info(self) -> dict:
        return dict(
            Address=self.sol_alt.address,
            Owner=self.sol_alt.owner,
            TxHash=self.neon_tx_hash,
        )


class SolAltDestroyer(ExecutorComponent):
    _finalize_sec: Final[int] = int(MIN_FINALIZE_SEC) * 2 + 1
    _deactivate_slot_cnt: Final[int] = 512 + 1
    _deactivate_sec: Final[int] = int(_deactivate_slot_cnt * ONE_BLOCK_SEC + 1) + _finalize_sec

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._new_alt_queue: list[_NeonAltInfo] = list()
        self._alt_queue: deque[_NeonAltInfo] = deque()

        self._stop_event = asyncio.Event()
        self._destroy_alt_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._destroy_alt_task = asyncio.create_task(self._destroy_alt_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._destroy_alt_task:
            await self._destroy_alt_task

    def destroy_alt_list(self, neon_alt_list: Sequence[NeonAltModel]) -> None:
        next_check_sec = self._get_now() + self._finalize_sec
        for neon_alt in neon_alt_list:
            alt = _NeonAltInfo(neon_alt.sol_alt_id, neon_alt.neon_tx_hash, next_check_sec, 0)
            with logging_context(**alt.ctx_id):
                msg = log_msg("add ALT {Address} (owner {Owner}, NeonTx {TxHash}) to the destroy queue", **alt.info)
                _LOG.debug(msg)
                self._new_alt_queue.append(alt)

    async def _destroy_alt_loop(self) -> None:
        with logging_context(ctx="destroy-alt"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop_event.wait(), self._finalize_sec)
                if self._stop_event.is_set():
                    break

                try:
                    await self._destroy_alt_queue()
                except BaseException as exc:
                    _LOG.error("unexpected error on destroy ALTs", exc_info=exc, extra=self._msg_filter)

    async def _destroy_alt_queue(self) -> None:
        if (not self._alt_queue) and (not self._new_alt_queue):
            return

        now = self._get_now()
        slot = await self._sol_client.get_slot(SolCommit.Finalized)
        new_destroy_queue: list[_NeonAltInfo] = list()

        while self._alt_queue and self._alt_queue[0].next_check_sec < now:
            alt = self._alt_queue.popleft()
            with logging_context(**alt.ctx_id):
                try:
                    next_check_sec = await self._destroy_alt(alt, slot)
                except BaseException as exc:
                    if not isinstance(exc, SolNoMoreRetriesError):
                        msg = log_msg(
                            "unexpected error on free ALT {Address} (owner {Owner}, NeonTx {TxHash})",
                            **alt.info,
                            exc_info=exc,
                            extra=self._msg_filter,
                        )
                        _LOG.warning(msg)
                    next_check_sec = self._get_now() + self._finalize_sec

            if next_check_sec:
                alt.next_check_sec = next_check_sec
                alt.attempt_cnt += 1
                new_destroy_queue.append(alt)

        if self._new_alt_queue:
            new_destroy_queue.extend(self._new_alt_queue)
            self._new_alt_queue = list()

        if new_destroy_queue:
            new_destroy_queue.extend(self._alt_queue)
            new_destroy_queue.sort(key=lambda x: x.next_check_sec)
            self._alt_queue = deque(new_destroy_queue)

    async def _destroy_alt(self, alt: _NeonAltInfo, slot: int) -> int:
        acct = await self._sol_client.get_alt_account(alt.sol_alt.address, SolCommit.Confirmed)
        if acct.is_empty:
            msg = log_msg("done destroy ALT {Address} (owner {Owner}, NeonTx {TxHash})", **alt.info)
            _LOG.debug(msg)
            return 0

        acct = await self._sol_client.get_alt_account(alt.sol_alt.address, SolCommit.Finalized)
        if alt.attempt_cnt >= 1024:
            msg = log_msg("too many attempts to destroy ALT {Address} (owner {Owner}, NeonTx {TxHash})", **alt.info)
            _LOG.warning(msg)
            return 0

        if not acct.is_deactivated:
            _LOG.debug("deactivate ALT")
            if await self._deactivate_alt(alt.sol_alt):
                return self._get_now() + self._deactivate_sec

        elif (slot - acct.deactivation_slot) > self._deactivate_slot_cnt:
            _LOG.debug("close ALT")
            await self._close_alt(alt.sol_alt)

        return self._get_now() + self._finalize_sec

    async def _deactivate_alt(self, alt: SolAltID) -> bool:
        ix = SolAltProg(alt.owner).make_deactivate_alt_ix(alt)
        tx = SolLegacyTx(name=SolAltIxCode.Deactivate.name + "ALT", ix_list=[ix])
        return await self._send_tx(alt, tx)

    async def _close_alt(self, alt: SolAltID) -> bool:
        ix = SolAltProg(alt.owner).make_close_alt_ix(alt)
        tx = SolLegacyTx(name=SolAltIxCode.Close.name + "ALT", ix_list=[ix])
        return await self._send_tx(alt, tx)

    async def _send_tx(self, alt: SolAltID, tx: SolLegacyTx) -> bool:
        tx_list_signer = OpTxListSigner(dict(alt=alt.ctx_id), alt.owner, self._op_client)
        watch_session = SolWatchTxSession(self._cfg, self._sol_client)
        return await SolTxListSender(self._cfg, watch_session, tx_list_signer).send(tuple([tx]))

    @staticmethod
    def _get_now() -> int:
        return int(time.monotonic())

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Final

from common.ethereum.hash import EthTxHash
from common.solana.alt_program import SolAltID
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context, log_msg
from .server_abc import MempoolComponent
from ..base.ex_api import NeonAltModel

_LOG = logging.getLogger(__name__)


class SolAltLoader(MempoolComponent):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._stop_event = asyncio.Event()
        self._scan_task: asyncio.Task | None = None

        self._alt_set: set[SolPubKey] = set()

    async def start(self) -> None:
        self._scan_task = asyncio.create_task(self._scan_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._scan_task:
            await self._scan_task

    async def _scan_loop(self) -> None:
        sleep_sec: Final[int] = 10
        with logging_context(ctx="scan-stuck-alt"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    await self._scan_stuck_alt()
                except BaseException as exc:
                    _LOG.error("unexpected error on scan stuck ALTs", exc_info=exc, extra=self._msg_filter)

    async def _scan_stuck_alt(self) -> None:
        _, alt_data_list = await self._db.get_stuck_neon_alt_list()
        new_alt_set: set[SolPubKey] = set()
        stuck_alt_list: list[NeonAltModel] = list()

        if not alt_data_list:
            self._alt_set = new_alt_set
            return

        req_id = dict(ctx="scan-stuck-alt")
        op_key_set = set(await self._op_client.get_signer_key_list(req_id))

        for data in alt_data_list:
            if "key" not in data:
                continue
            elif not data.get("is_stuck", False):
                continue

            owner = SolPubKey.from_raw(data["operator"])
            if owner.is_empty:
                # indexer didn't find a owner of the ALT
                continue

            neon_tx_hash = EthTxHash.from_raw(data["neon_tx_hash"])
            addr = SolPubKey.from_raw(data["key"])
            new_alt_set.add(addr)

            if addr in self._alt_set:
                # skip, if it was loaded before
                continue
            elif owner not in op_key_set:
                # skip tables from other operators
                continue

            tx = neon_tx_hash.to_bytes()[:4].hex()
            alt = SolAltID(address=addr, owner=owner, recent_slot=0, nonce=0)
            with logging_context(alt=alt.ctx_id, tx=tx):
                msg = log_msg(
                    "found stuck ALT {Address} (owner {Owner}, NeonTx {TxHash})",
                    Address=addr,
                    Owner=owner,
                    TxHash=neon_tx_hash,
                )
                _LOG.debug(msg)
                stuck_alt_list.append(NeonAltModel(neon_tx_hash=neon_tx_hash, sol_alt_id=alt))

        self._alt_set = new_alt_set
        if stuck_alt_list:
            await self._exec_client.destroy_alt_list(req_id, stuck_alt_list)

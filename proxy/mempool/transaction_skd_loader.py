import asyncio
import contextlib
import copy
import logging
from typing import Final

from common.config.constants import ONE_BLOCK_SEC, MIN_FINALIZE_BLOCK
from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .server_abc import MempoolComponent, MempoolServerAbc
from .transaction_executor import MpTxExecutor
from ..base.ex_api import ExecTokenModel
from ..base.mp_api import MpTxModel, MpTokenGasPriceModel

_LOG = logging.getLogger(__name__)


class MpSkdTxLoader(MempoolComponent):
    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)
        self._start_slot = 0
        self._layer0_chain_id = 0
        self._stop_event = asyncio.Event()
        self._scan_skd_tx_task: asyncio.Task | None = None

    async def start(self) -> None:
        evm_cfg = await self._get_evm_cfg()
        self._layer0_chain_id = evm_cfg.layer0_chain_id

        if not self._cfg.mp_skip_stuck_tx:
            self._scan_skd_tx_task = asyncio.create_task(self._scan_skd_tx_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._scan_skd_tx_task:
            await self._scan_skd_tx_task

    @cached_property
    def _tx_executor(self) -> MpTxExecutor:
        return self._server._tx_executor  # noqa

    @property
    def _token_gas_price(self) -> MpTokenGasPriceModel | None:
        return self._gas_price.chain_dict.get(self._layer0_chain_id, None)

    async def _get_slot_out(self) -> int:
        evm_cfg = await self._get_evm_cfg()
        return evm_cfg.tree_account_slot_out

    async def _scan_skd_tx_loop(self) -> None:
        sleep_sec: Final[float] = ONE_BLOCK_SEC
        idx = 0
        with logging_context(ctx="mp-scan-skd-txs"):
            while True:
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                try:
                    await self._scan_new_skd_tx()

                    if (idx := idx + 1) >= MIN_FINALIZE_BLOCK:
                        await self._scan_old_skd_tx()
                        idx = 0

                except BaseException as exc:
                    _LOG.error("error on scan", exc_info=exc)

    async def _scan_new_skd_tx(self) -> None:
        if not self._token_gas_price:
            return

        skd_tx_list = await self._db.get_neon_skd_tx_list(self._start_slot, 1000)

        start_slot = 0
        for skd_tx in skd_tx_list:
            start_slot = max(start_slot, skd_tx.slot)

            mp_tx = MpTxModel.from_skd_tx(skd_tx, self._layer0_chain_id)
            payer = NeonAddress.from_raw(mp_tx.payer, mp_tx.chain_id)
            neon_acct = await self._core_api_client.get_neon_account(payer, None)

            with logging_context(tx=mp_tx.tx_id, skd_tree=skd_tx.tree_address.ident):
                await self._tx_executor.schedule_tx_request(mp_tx, neon_acct.state_tx_cnt, neon_acct.balance)
        self._start_slot = start_slot

    async def _scan_old_skd_tx(self) -> None:
        if (token_gas_price := self._token_gas_price) is None:
            return

        token = ExecTokenModel.from_raw(self._gas_price, token_gas_price)

        slot_out = await self._get_slot_out()
        current_slot = await self._sol_client.get_slot()
        min_slot = current_slot - slot_out
        skd_tx_list = await self._db.get_old_neon_skd_tx_list_by_slot(min_slot, 100)

        for skd_tx in skd_tx_list:
            if skd_tx.rlp_tx:
                mp_tx = MpTxModel.from_skd_tx(skd_tx, self._layer0_chain_id)
                await self._exec_client.exec_tx(mp_tx, token)
            else:
                await self._exec_client.destroy_tree_account(skd_tx, token)

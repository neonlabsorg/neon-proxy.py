from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.utils.json_logger import logging_context, log_msg
from .server_abc import MempoolServerAbc, MempoolComponent
from .transaction_dict import MpTxDict
from .transaction_schedule import MpTxSchedule
from .transaction_stuck_dict import MpStuckTxDict
from ..base.ex_api import ExecTxRespCode, ExecTxResp
from ..base.mp_api import MpTxResp, MpTxRespCode, MpTxPoolContentResp, MpTxModel, MpStuckTxModel, MpGasPriceModel
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


class MpTxExecutor(MempoolComponent):
    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)

        self._tx_schedule_idx = 0
        self._tx_schedule_dict: dict[int, MpTxSchedule] = dict()
        self._tx_dict = MpTxDict(self._cfg)
        self._stuck_tx_dict = MpStuckTxDict()

        self._stop_event = asyncio.Event()
        self._exec_event = asyncio.Event()
        self._tx_exec_task: asyncio.Task | None = None
        self._exec_task_dict: dict[EthTxHash, asyncio.Task] = dict()
        self._completed_task_list: list[asyncio.Task] = list()

    async def start(self) -> None:
        await self._tx_dict.start()
        if not self._cfg.mp_skip_stuck_tx:
            await self._stuck_tx_dict.start(self._db),
        self._tx_exec_task = asyncio.create_task(self._tx_exec_loop())

    async def close(self) -> None:
        self._stop_event.set()
        self._exec_event.set()

        task_list = (
            [self._stuck_tx_dict.close(), self._tx_dict.close(), self._tx_exec_task]
            + [schedule.close() for schedule in self._tx_schedule_dict.values()]
            + self._completed_task_list
        )
        for task in self._exec_task_dict.values():
            task.cancel()
        await asyncio.gather(*task_list)

    async def schedule_tx_request(self, tx: MpTxModel, state_tx_cnt: int) -> MpTxResp:
        try:
            if self._tx_dict.get_tx_by_hash(tx.neon_tx_hash) is not None:
                # _LOG.debug("tx is already known")
                return MpTxResp(code=MpTxRespCode.AlreadyKnown, state_tx_cnt=None)

            if result := await self._update_tx_order(tx):
                return result

            if not (tx_schedule := self._tx_schedule_dict.get(tx.chain_id)):
                tx_schedule = MpTxSchedule(self._cfg, self._core_api_client, tx.chain_id)
                self._tx_schedule_dict[tx.chain_id] = tx_schedule
                await tx_schedule.start()

            if not (result := tx_schedule.add_tx(tx, state_tx_cnt)):
                return MpTxResp(code=MpTxRespCode.UnknownChainID, state_tx_cnt=None)
            elif result.code == MpTxRespCode.Success:
                self._tx_dict.add_tx(tx)

            return result

        except BaseException as exc:
            _LOG.error("error on schedule tx", exc_info=exc)
            return MpTxResp(code=MpTxRespCode.Unspecified, state_tx_cnt=None)

        finally:
            self._exec_event.set()

    def get_pending_tx_cnt(self, sender: NeonAccount) -> int | None:
        return self._call_tx_schedule(sender.chain_id, MpTxSchedule.get_pending_tx_cnt, sender.eth_address)

    def get_last_tx_cnt(self, sender: NeonAccount) -> int | None:
        return self._call_tx_schedule(sender.chain_id, MpTxSchedule.get_last_tx_cnt, sender.eth_address)

    def get_tx_by_hash(self, neon_tx_hash: EthTxHash) -> NeonTxModel | None:
        return self._tx_dict.get_tx_by_hash(neon_tx_hash)

    def get_tx_by_sender_nonce(self, sender: NeonAccount, tx_nonce: int) -> NeonTxModel | None:
        return self._tx_dict.get_tx_by_sender_nonce(sender, tx_nonce)

    def get_content(self) -> MpTxPoolContentResp:
        pending_list = list()
        queued_list = list()
        for tx_schedule in self._tx_schedule_dict.values():
            cont = tx_schedule.get_content()
            pending_list.extend(cont.pending_list)
            queued_list.extend(cont.queued_list)
        return MpTxPoolContentResp(pending_list=tuple(pending_list), queued_list=tuple(queued_list))

    async def _update_tx_order(self, tx: MpTxModel) -> MpTxResp | None:
        if not tx.neon_tx.has_chain_id:
            _LOG.debug("increase gas-price for wo-chain-id-tx (for sorting in scheduling queue)")
        elif not tx.gas_price:
            _LOG.debug("increase gas-price for fee-less-tx (for sorting in scheduling queue)")
        else:
            return None

        gas_price = self._server.get_gas_price()
        if not (token := gas_price.chain_dict.get(tx.chain_id, None)):
            _LOG.warning("unknown chainID: 0x%x", tx.chain_id)
            return MpTxResp(code=MpTxRespCode.UnknownChainID, state_tx_cnt=None)

        # this gas-price is used only for sorting,
        #  without this increasing
        #  the tx will be in the bottom of the execution queue,
        #  and as a result, it will be never executed
        tx.set_gas_price(token.suggested_gas_price * 2)
        return None

    def _call_tx_schedule(self, chain_id: int, method, *args):
        if tx_schedule := self._tx_schedule_dict.get(chain_id, None):
            return method(tx_schedule, *args)
        if chain_id not in self._server.get_gas_price().token_dict:
            _LOG.warning("unknown chainID: 0x%x", chain_id)
        return None

    async def _tx_exec_loop(self):
        sleep_sec: Final[float] = ONE_BLOCK_SEC
        while True:
            try:
                self._exec_event.clear()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._exec_event.wait(), sleep_sec)
                if self._stop_event.is_set():
                    break

                gas_price = self._server.get_gas_price()
                while (await self._acquire_stuck_tx()) or (await self._acquire_scheduled_tx(gas_price)):
                    continue

                task_list, self._completed_task_list = self._completed_task_list, list()
                if task_list:
                    await asyncio.gather(*task_list)

                # TODO: add statistics

            except BaseException as exc:
                _LOG.error("error on process schedule", exc_info=exc)

    async def _acquire_stuck_tx(self) -> bool:
        if self._cfg.mp_skip_stuck_tx:
            return False

        if not (stuck_tx := self._stuck_tx_dict.peek_tx()):
            return False

        with logging_context(tx=stuck_tx.tx_id):
            if tx := self._tx_dict.get_tx_by_hash(stuck_tx.neon_tx_hash):
                result = self._call_tx_schedule(tx.chain_id, MpTxSchedule.drop_tx, tx.from_address, tx.nonce)
                if not result:
                    self._stuck_tx_dict.skip_tx(stuck_tx)
                    return True
                self._tx_dict.done_tx(tx.neon_tx_hash)

            resource = await self._op_client.get_resource(stuck_tx.tx_id, None)
            if resource.is_empty:
                return False

            tx_hash = stuck_tx.neon_tx_hash
            assert tx_hash not in self._exec_task_dict

            self._stuck_tx_dict.acquire_tx(stuck_tx)
            self._exec_task_dict[tx_hash] = asyncio.create_task(self._exec_stuck_tx(stuck_tx, resource))

        return True

    async def _exec_stuck_tx(self, stuck_tx: MpStuckTxModel, resource: OpResourceModel) -> None:
        with logging_context(tx=stuck_tx.tx_id):
            await self._exec_stuck_tx_impl(stuck_tx, resource)

    async def _exec_stuck_tx_impl(self, stuck_tx: MpStuckTxModel, resource: OpResourceModel) -> None:
        try:
            resp = await self._exec_client.complete_stuck_tx(stuck_tx, resource)
        except BaseException as exc:
            resp = ExecTxResp(code=ExecTxRespCode.Failed)
            _LOG.error("error on send stuck NeonTx to executor", exc_info=exc)

        msg = log_msg(
            "done stuck tx {StuckTx}, result {Result}, time {TimeMS} msec",
            StuckTx=stuck_tx,
            Result=resp,
            TimeMS=stuck_tx.process_time_msec,
        )
        if resp.code == ExecTxRespCode.Done:
            _LOG.debug(msg)
        else:
            _LOG.warning(msg)

        is_good_resource = True
        if resp.code == ExecTxRespCode.BadResource:
            is_good_resource = False
            self._stuck_tx_dict.cancel_tx(stuck_tx)
        elif resp.code == ExecTxRespCode.Failed:
            self._stuck_tx_dict.fail_tx(stuck_tx)
        elif resp.code == ExecTxRespCode.Done:
            self._stuck_tx_dict.done_tx(stuck_tx)
        else:
            _LOG.error("unknown exec response code %s", resp)
            self._stuck_tx_dict.fail_tx(stuck_tx)

        await self._op_client.free_resource(stuck_tx.tx_id, is_good_resource, resource)
        if task := self._exec_task_dict.pop(stuck_tx.neon_tx_hash, None):
            self._completed_task_list.append(task)
        else:
            _LOG.error("unknown task %s", stuck_tx.neon_tx_hash)
        self._exec_event.set()

    async def _acquire_scheduled_tx(self, gas_price: MpGasPriceModel) -> bool:
        tx_schedule_list: list[MpTxSchedule] = list(self._tx_schedule_dict.values())

        for retry in range(len(tx_schedule_list)):
            if self._tx_schedule_idx >= len(tx_schedule_list):
                self._tx_schedule_idx = 0

            tx_schedule = tx_schedule_list[self._tx_schedule_idx]
            self._tx_schedule_idx += 1
            if not tx_schedule.tx_cnt:
                continue

            if not (token := gas_price.chain_dict.get(tx_schedule.chain_id, None)):
                _LOG.warning("unknown chainID: 0x%x", tx_schedule.chain_id)
                continue

            tx = tx_schedule.peek_top_tx()
            if (not tx) or (tx.gas_price < token.min_executable_gas_price):
                continue
            assert tx.neon_tx_hash not in self._exec_task_dict

            resource = await self._op_client.get_resource(tx.tx_id, tx.chain_id)
            if resource.is_empty:
                break

            tx_schedule.acquire_tx(tx)
            self._exec_task_dict[tx.neon_tx_hash] = asyncio.create_task(self._exec_scheduled_tx(tx, resource))
            return True

        return False

    async def _exec_scheduled_tx(self, tx: MpTxModel, resource: OpResourceModel) -> None:
        with logging_context(tx=tx.tx_id):
            await self._exec_scheduled_tx_impl(tx, resource)

    async def _exec_scheduled_tx_impl(self, tx: MpTxModel, resource: OpResourceModel) -> None:
        try:
            resp = await self._exec_client.exec_tx(tx, resource)
        except BaseException as exc:
            resp = ExecTxResp(code=ExecTxRespCode.Failed)
            _LOG.error("error on send NeonTx to executor", exc_info=exc)
        else:
            msg = log_msg(
                "done tx {Tx}, result {Result}, time {TimeMS} msec",
                Tx=tx,
                Result=resp,
                TimeMS=tx.process_time_msec,
            )
            if resp.code == ExecTxRespCode.Failed:
                _LOG.warning(msg)
            else:
                _LOG.debug(msg)

        if resp.code not in (ExecTxRespCode.BadResource, ExecTxRespCode.NonceTooHigh):
            self._tx_dict.done_tx(tx.neon_tx_hash)

        is_good_resource = True
        if resp.code == ExecTxRespCode.BadResource:
            is_good_resource = False
            action = MpTxSchedule.cancel_tx
        elif resp.code == ExecTxRespCode.NonceTooHigh:
            action = MpTxSchedule.cancel_tx
        elif resp.code in (ExecTxRespCode.Failed, ExecTxRespCode.NonceTooLow):
            action = MpTxSchedule.fail_tx
        elif resp.code == ExecTxRespCode.Done:
            action = MpTxSchedule.done_tx
        else:
            action = MpTxSchedule.fail_tx
            _LOG.error("unknown exec response code %s", resp)

        self._call_tx_schedule(tx.chain_id, action, tx, resp.state_tx_cnt)
        await self._op_client.free_resource(tx.tx_id, is_good_resource, resource)

        if task := self._exec_task_dict.pop(tx.neon_tx_hash, None):
            self._completed_task_list.append(task)
        else:
            _LOG.error("unknown task %s", tx.neon_tx_hash)
        self._exec_event.set()

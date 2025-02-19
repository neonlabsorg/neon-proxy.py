from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Union, Sequence, Generic, TypeVar, Final, Any

import aiohttp as _ws
import solders.account_decoder as _acct
import solders.errors as _err
import solders.rpc.config as _cfg
import solders.rpc.requests as _req
import solders.rpc.responses as _resp
from typing_extensions import Self

from .client import SolClient
from ..config.config import Config
from ..config.constants import ONE_BLOCK_SEC
from ..config.utils import LogMsgFilter
from ..http.utils import HttpURL, HttpStrOrURL
from ..solana.account import SolAccountModel
from ..solana.commit_level import SolCommit
from ..solana.errors import SolError
from ..solana.pubkey import SolPubKey
from ..solana.signature import SolTxSig
from ..solana.transaction import SolTx
from ..utils.json_logger import logging_context

_LOG = logging.getLogger(__name__)

_SoldersTxSigCfg = _cfg.RpcSignatureSubscribeConfig
_SoldersSubTxSig = _req.SignatureSubscribe
_SoldersUnsubTxSig = _req.SignatureUnsubscribe

_SoldersAcctCfg = _cfg.RpcAccountInfoConfig
_SoldersAcctEnc = _acct.UiAccountEncoding
_SoldersSubAcct = _req.AccountSubscribe
_SoldersUnsubAcct = _req.AccountUnsubscribe

_SoldersSubSlot = _req.SlotSubscribe
_SoldersUnsubSlot = _req.SlotUnsubscribe

_SoldersSubResult = _resp.SubscriptionResult
_SoldersSubError = _resp.SubscriptionError
_SoldersUnsubResult = _resp.UnsubscribeResult

_SoldersNotif = _resp.Notification
_SoldersTxSigNotif = _resp.SignatureNotification
_SoldersAcctNotif = _resp.AccountNotification
_SoldersSlotNotif = _resp.SlotNotification
_SoldersSlotInfo = _resp.SlotInfo

_WsSession = _ws.ClientWebSocketResponse
_WsMsgType = _ws.WSMsgType

_SolWsSendData = Union[
    _SoldersSubTxSig,
    _SoldersUnsubTxSig,
    _SoldersSubAcct,
    _SoldersUnsubAcct,
    _SoldersSubSlot,
    _SoldersUnsubSlot,
]
_SolWsSubNotif = Union[_SoldersTxSigNotif, _SoldersAcctNotif, _SoldersSlotNotif]

_SoldersWsMsg = _resp.WebsocketMessage
_SolWsObjKey = TypeVar("_SolWsObjKey")
_SolWsObj = TypeVar("_SolWsObj")


@dataclass(frozen=True)
class _SolWsObjInfo(Generic[_SolWsObjKey, _SolWsObj]):
    req_id: int | None
    sub_id: int | None
    key: _SolWsObjKey | None
    obj: _SolWsObj | None
    commit: SolCommit


class _SolWsSession(Generic[_SolWsObjKey, _SolWsObj]):
    _ObjInfo = _SolWsObjInfo[_SolWsObjKey, _SolWsObj]
    _empty_info: Final[_ObjInfo] = _SolWsObjInfo(None, None, None, None, SolCommit.Confirmed)

    def __init__(self, cfg: Config, sol_client: SolClient, *, ws_endpoint: HttpStrOrURL | None = None) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._ws_endpoint = ws_endpoint
        self._msg_filter = LogMsgFilter(cfg)

        self._id = itertools.count()
        self._ws_session: _WsSession | None = None

        self._req_dict: dict[int, _SolWsObjKey] = dict()
        self._sub_dict: dict[int, _SolWsObjKey] = dict()
        self._obj_dict: dict[_SolWsObjKey, _SolWsObjInfo[_SolWsObjKey, _SolWsObj]] = dict()

        self._err_obj_dict: dict[_SolWsObjKey, _SolWsObjInfo[_SolWsObjKey, _SolWsObj]] = dict()
        self._err_handler_next_nsec: int = 0
        self._is_err_handler_active: bool = False

        self._update_future: asyncio.Future[Any] | None = None
        self._close_future: asyncio.Future[Any] | None = None

    @property
    def sol_client(self) -> SolClient:
        return self._sol_client

    @property
    def is_connected(self) -> bool:
        return bool(self._ws_session) and (not self._ws_session.closed)

    @property
    def is_empty(self) -> bool:
        return (not self._obj_dict) and (not self._err_obj_dict)

    async def connect(self) -> None:
        if self.is_connected:
            return

        ws_endpoint = HttpURL(self._ws_endpoint or self._cfg.random_sol_ws_url)

        # _LOG.debug("connecting to WebSocket %s...", ws_endpoint, extra=self._msg_filter)
        ws_session = await self._sol_client.session.ws_connect(ws_endpoint)
        self._ws_session = ws_session
        # _LOG.debug("connected to WebSocket")

    async def safe_connect(self) -> bool:
        try:
            await self.connect()
            return True
        except (BaseException,):
            return False

    async def disconnect(self) -> None:
        if not self.is_connected:
            self._ws_session = None
            self._clear()
            return

        # _LOG.debug("closing WebSocket connection...")
        ws_session, self._ws_session = self._ws_session, None

        self._clear()
        await ws_session.close()
        # _LOG.debug("closed WebSocket connection")

    async def safe_disconnect(self) -> bool:
        try:
            await self.disconnect()
            return True
        except (BaseException,):
            return False

    async def update(self, *, timeout_nsec: int = 1) -> None:
        if future := self._update_future:
            await future
            return

        self._update_future = asyncio.get_event_loop().create_future()
        try:
            await self._err_handler()
            await self._wait(timeout_nsec, time.monotonic_ns())
        finally:
            future, self._update_future = self._update_future, None
            if future:
                future.set_result(None)

    async def _err_handler(self) -> None:
        if not (await self.safe_connect()):
            return

        if self._is_err_handler_active or (self._err_handler_next_nsec > time.monotonic_ns()):
            return
        self._is_err_handler_active = True

        try:
            # resubscribe on objects from containers with errors
            err_obj_dict, self._err_obj_dict = self._err_obj_dict, dict()
            for item in err_obj_dict.values():
                await self._sub_obj(item.key, item.obj, item.commit)
        finally:
            self._err_handler_next_nsec = time.monotonic_ns() + int(pow(10, 9) * ONE_BLOCK_SEC)
            self._is_err_handler_active = False

    async def __aenter__(self) -> Self:
        await self.safe_connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> Self:
        await self.safe_disconnect()
        if exc_val:
            raise
        return self

    async def _ws_receive_data(self, timeout_sec: float | None) -> Sequence[_SoldersWsMsg]:
        if not self.is_connected:
            await asyncio.sleep(0)
            return tuple()

        # aiohttp's receive_str throws a very cryptic error when the
        # connection is closed while we are waiting
        # handle that ourselves
        try:
            msg = await self._ws_session.receive(timeout_sec)
        except asyncio.TimeoutError:
            return tuple()

        msg_type = msg.type
        if msg_type in (_WsMsgType.CLOSED, _WsMsgType.CLOSING):
            _LOG.debug("WebSocket closed while waiting for message")
            await self._on_close()
            return tuple()
        elif msg_type != _WsMsgType.TEXT:
            raise SolError(f"Unexpected WebSocket message type {msg_type}")

        try:
            return tuple(_resp.parse_websocket_message(msg.data))
        except _err.SerdeJSONError:
            _LOG.warning("unexpected error on parsing websocket message: %s", msg.data)
        except (BaseException,):
            _LOG.warning("unexpected error on parsing websocket message: %s", msg.data)
        return tuple()

    async def _wait(self, timeout_nsec: int, now_nsec: int) -> None:
        if not (item_list := await self._ws_receive_data(timeout_nsec / 1e9)):
            return

        for item in item_list:
            if isinstance(item, _SoldersSubError):
                if key := self._req_dict.pop(item.id, None):
                    info = self._obj_dict.pop(key, self._empty_info)
                    assert info.sub_id not in self._sub_dict, f"subscription {info.sub_id} for {key} already exists?"

                    # Error from Solana nodes with a BigTable...
                    if item.error not in _resp.RpcCustomErrorFieldless.NoSnapshot:
                        _LOG.warning("got error %s for %s", item.error, key)
                    self._err_obj_dict[info.key] = info
                else:
                    _LOG.warning("unknown request %s on error", item.id)
            elif isinstance(item, _SoldersSubResult):
                if key := self._req_dict.pop(item.id, None):
                    info = self._obj_dict.pop(key, self._empty_info)
                    assert not info.sub_id, f"subscription {info.sub_id} for {key} already exists?"
                    assert item.result not in self._sub_dict, f"subscription {item.result} for {key} already exists?"

                    self._sub_dict[item.result] = key
                    info = _SolWsObjInfo(key=key, obj=info.obj, req_id=item.id, sub_id=item.result, commit=info.commit)
                    self._obj_dict[key] = info
                    # _LOG.debug("got subscription %s for %s", item.result, key)
                else:
                    # _LOG.warning("unknown request %s for result %s", item.id, item.result)
                    await self._unsub(item.result)
            elif isinstance(item, _SolWsSubNotif):
                if key := self._sub_dict.pop(item.subscription, None):
                    info = self._obj_dict.pop(key, self._empty_info)
                    assert info.req_id not in self._req_dict, f"request {info.req_id} for {key} still exists?"
                    # _LOG.debug("got notification %s", key)
                    self._on_sub_notif(info, item, now_nsec)
                else:
                    _LOG.warning("unknown subscription %s on notification", item.subscription)

    def _has_obj(self, key: _SolWsObjKey) -> bool:
        return (key in self._obj_dict) or (key in self._err_obj_dict)

    async def _sub_obj(self, key: _SolWsObjKey, obj: _SolWsObj | None, commit: SolCommit) -> None:
        if self._has_obj(key):
            return

        info = self._new_info(key, obj, commit)
        if not self.is_connected:
            self._err_obj_dict[key] = info
            return

        self._req_dict[info.req_id] = key
        self._obj_dict[key] = info
        req = self._new_sub_request(info, commit)

        try:
            # _LOG.debug("subscribe %s on tx %s", sig_info.req_id, tx)
            await self._ws_session.send_str(req.to_json())
        except (BaseException,):
            # _LOG.error("ERROR subscribe %s", str(e), exc_info=e)
            self._obj_dict.pop(key, None)
            self._req_dict.pop(info.req_id, None)
            self._err_obj_dict[key] = info

    def _new_info(self, key: _SolWsObjKey, obj: _SolWsObj | None, commit: SolCommit) -> _SolWsObjInfo:
        req_id = next(self._id)
        return _SolWsObjInfo(key=key, obj=obj, req_id=req_id, sub_id=None, commit=commit)

    async def _unsub_obj(self, key: _SolWsObjKey) -> None:
        self._err_obj_dict.pop(key, None)
        if not (info := self._obj_dict.pop(key, None)):
            return

        self._req_dict.pop(info.req_id, None)
        if not self._sub_dict.pop(info.sub_id, None):
            return
        elif not self.is_connected:
            return

        await self._unsub(info.sub_id)

    async def _unsub(self, sub_id: int) -> None:
        req_id = next(self._id)
        req = self._new_unsub_request(req_id, sub_id)
        try:
            await self._ws_session.send_str(req.to_json())
        except (BaseException,):
            # _LOG.error("ERROR unsubscribe %s", str(e), exc_info=e)
            pass

    def _clear(self) -> None:
        self._sub_dict, self._req_dict, self._obj_dict, self._err_obj_dict = dict(), dict(), dict(), dict()

    async def _on_close(self) -> None:
        if future := self._close_future:
            await future
            return

        self._close_future = asyncio.get_event_loop().create_future()
        # move all objects to the error dictionary
        #  they will be restored on in _err_handler
        err_obj_dict, self._err_obj_dict = self._err_obj_dict, dict()
        obj_dict, self._obj_dict = self._obj_dict, dict()
        for key, obj in self._obj_dict.items():
            err_obj_dict[key] = obj

        await self.safe_disconnect()

        self._err_obj_dict = err_obj_dict
        future, self._close_future = self._close_future, None
        future.set_result(None)

    # fmt: off
    def _on_sub_notif(self, info: _ObjInfo, data: _SolWsSubNotif, now_nsec: int) -> None: ...
    def _new_sub_request(self, info: _ObjInfo, commit: SolCommit) -> _SolWsSendData: ...
    def _new_unsub_request(self, req_id: int, sub_id: int) -> _SolWsSendData: ...
    # fmt: on


class SolWatchTxSession(_SolWsSession[SolTxSig, SolTx]):
    _TxInfo = _SolWsObjInfo[SolTxSig, SolTx]

    async def wait_for_tx_receipt_list(
        self,
        tx_list: Sequence[SolTx],
        commit: SolCommit,
        timeout_sec: float,
    ) -> bool:
        async with self:
            try:
                for tx in tx_list:
                    await self._sub_obj(tx.sig, tx, commit)

                return await self._wait_for_tx_list_update(timeout_sec)
            except BaseException as exc:
                _LOG.error("error on waiting statuses for txs", exc_info=exc)
                return False

    async def _wait_for_tx_list_update(self, timeout_sec: float) -> bool:
        start_time_nsec, timeout_nsec = time.monotonic_ns(), int(timeout_sec * 1e9)
        # _LOG.debug("OBJ %s %s", len(self._obj_dict), timeout_sec)
        while not self.is_empty:
            await self._err_handler()

            now_nsec = time.monotonic_ns()
            if (wait_nsec := timeout_nsec - (now_nsec - start_time_nsec)) <= 0:
                return False
            await self._wait(wait_nsec, now_nsec)
        return True

    def _new_sub_request(self, info: _TxInfo, commit: SolCommit) -> _SolWsSendData:
        cfg = _SoldersTxSigCfg(commit.to_rpc_commit())
        return _SoldersSubTxSig(info.key, cfg, info.req_id)

    def _new_unsub_request(self, req_id: int, sub_id: int) -> _SolWsSendData:
        return _SoldersUnsubTxSig(sub_id, req_id)


class SolWatchAccountSession(_SolWsSession[SolPubKey, SolAccountModel]):
    @dataclass(frozen=True)
    class _RecheckAcctInfo:
        key: SolPubKey
        insert_nsec: int

    _AcctInfo = _SolWsObjInfo[SolPubKey, SolAccountModel]

    def __init__(self, *args, **kwargs) -> None:
        commit = kwargs.pop("commit", SolCommit.Confirmed)
        update_nsec = int(kwargs.pop("force_check_sec", 0) * pow(10, 9))
        has_update_queue = (update_nsec > 0) or kwargs.pop("has_update_queue", False)
        init_acct = kwargs.pop("init_account", False)
        super().__init__(*args, **kwargs)
        self._commit = commit
        self._force_update_nsec = update_nsec
        self._has_update_queue = has_update_queue
        self._init_acct = init_acct
        self._recheck_queue: deque[SolWatchAccountSession._RecheckAcctInfo] = deque()
        self._chg_key_set: set[SolPubKey] = set()

    async def subscribe_account(self, addr: SolPubKey) -> None:
        if self._has_obj(addr):
            return

        await self.safe_connect()
        await self._sub_obj(addr, None, self._commit)

    async def unsubscribe_account(self, addr: SolPubKey) -> None:
        await self._unsub_obj(addr)
        self._chg_key_set.discard(addr)

    def get_account(self, addr: SolPubKey) -> SolAccountModel | None:
        if addr.is_empty:
            return None
        elif info := self._obj_dict.get(addr, None):
            return info.obj
        elif info := self._err_obj_dict.get(addr, None):
            return info.obj
        return None

    def pop_changed_key_list(self) -> Sequence[SolPubKey]:
        key_list, self._chg_key_set = list(self._chg_key_set), set()

        last_nsec = time.monotonic_ns() - self._force_update_nsec
        while self._recheck_queue and (self._recheck_queue[0].insert_nsec <= last_nsec):
            key_list.append(self._recheck_queue.popleft().key)

        return tuple(key_list)

    async def _sub_obj(self, key: SolPubKey, obj: SolAccountModel | None, commit: SolCommit) -> None:
        if self._has_obj(key):
            return

        acct = await self._sol_client.get_account(key, commit=self._commit) if self._init_acct else obj
        await super()._sub_obj(key, acct, commit)
        self._chg_key_set.add(key)

    def _on_sub_notif(self, info: _AcctInfo, data: _SoldersAcctNotif, now_nsec: int) -> None:
        acct = SolAccountModel.from_raw(info.key, data.result.value)
        info = _SolWsObjInfo(req_id=info.req_id, sub_id=info.sub_id, key=info.key, obj=acct, commit=info.commit)
        self._obj_dict[info.key] = info
        self._sub_dict[info.sub_id] = info.key

        if info.key not in self._chg_key_set:
            self._chg_key_set.add(info.key)
        if self._force_update_nsec:
            self._recheck_queue.append(self._RecheckAcctInfo(info.key, now_nsec))

    def _new_sub_request(self, info: _AcctInfo, commit: SolCommit) -> _SolWsSendData:
        cfg = _SoldersAcctCfg(encoding=_SoldersAcctEnc.Base64, commitment=commit.to_rpc_commit())
        return _SoldersSubAcct(info.key, cfg, info.req_id)

    def _new_unsub_request(self, req_id: int, sub_id: int) -> _SolWsSendData:
        return _SoldersUnsubAcct(sub_id, req_id)


class SolWatchSlotSession(_SolWsSession[int, None]):
    _SlotInfo = _SolWsObjInfo[int, None]

    @dataclass(frozen=True)
    class _SlotWaitTask:
        slot: commit
        commit: SolCommit
        future: asyncio.Future

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._data: _SoldersSlotInfo | None = None
        self._prev_root: int | None = None
        self._update_task: asyncio.Task | None = None
        self._is_started = False
        self._wait_slot_queue: list[SolWatchSlotSession._SlotWaitTask] = list()

    async def start(self) -> None:
        if self._update_task:
            return
        self._is_started = True

        await self._sub_slot(init_start_slot=True)
        self._update_task = asyncio.create_task(self._update_loop())

    async def stop(self) -> None:
        if not self._update_task:
            return

        update_task, self._update_task, self._is_started = self._update_task, None, False
        await update_task

    async def update(self, *, timeout_nsec: int = int(2 * ONE_BLOCK_SEC * 1e9)) -> None:
        await self._sub_slot()
        await super().update(timeout_nsec=timeout_nsec)

        wait_slot_queue, self._wait_slot_queue = self._wait_slot_queue, list()
        for task in wait_slot_queue:
            if self._is_complete(task.slot, task.commit):
                task.future.set_result(None)
            else:
                self._wait_slot_queue.append(task)

    async def wait_for_slot(self, slot: int, commit: SolCommit) -> None:
        if self._is_complete(slot, commit):
            await asyncio.sleep(0)
            return

        future = asyncio.get_event_loop().create_future()
        task = self._SlotWaitTask(slot, commit, future)
        self._wait_slot_queue.append(task)
        await future

    @property
    def processed_slot(self) -> int:
        return self._data.slot

    @property
    def confirmed_slot(self) -> int:
        return self._data.parent

    @property
    def finalized_slot(self) -> int:
        return self._data.root

    def _is_complete(self, slot: int, commit: SolCommit) -> bool:
        return self._get_slot(commit) >= slot

    def _get_slot(self, commit: SolCommit) -> int | None:
        if commit == SolCommit.Confirmed:
            return self.confirmed_slot
        elif commit == SolCommit.Finalized:
            return self.finalized_slot
        elif commit == SolCommit.Processed:
            return self.processed_slot
        assert False, f"unknown commit {commit}"

    async def _sub_slot(
        self, *,
        init_start_slot=False,
        confirmed_slot=0,
        finalized_slot=0,
    ) -> None:
        if self._data and (not self.is_empty):
            return

        _LOG.debug("subscribe on slot update")
        await self.safe_connect()

        if self._data or init_start_slot:
            confirmed_slot, finalized_slot = await asyncio.gather(*[
                self._sol_client.get_slot(SolCommit.Confirmed),
                self._sol_client.get_slot(SolCommit.Finalized),
            ])
        self._data = _SoldersSlotInfo(confirmed_slot, 0, finalized_slot)

        await self._sub_obj(1, None, SolCommit.Confirmed)

    async def _update_loop(self) -> None:
        with logging_context(ctx="update-slot"):
            while self._is_started:
                try:
                    await self.update()
                except BaseException as exc:
                    _LOG.error("unexpected error on update slot", exc_info=exc, extra=self._msg_filter)

    def _new_sub_request(self, info: _SlotInfo, commit: SolCommit) -> _SolWsSendData:
        return _SoldersSubSlot(info.req_id)

    def _on_sub_notif(self, info: _SlotInfo, data: _SoldersSlotNotif, now_nsec: int) -> None:
        new_data = data.result
        if self._prev_root:
            self._data = _SoldersSlotInfo(new_data.slot, new_data.parent, self._prev_root)

        self._prev_root = new_data.root
        self._obj_dict[info.key] = info
        self._sub_dict[info.sub_id] = info.key

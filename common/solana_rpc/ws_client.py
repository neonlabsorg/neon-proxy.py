from __future__ import annotations

import asyncio
import itertools
import logging
import time
from dataclasses import dataclass
from typing import Union, Sequence, Literal, Generic, TypeVar, Final, Any
from collections import deque

import aiohttp as _ws
import pydantic as _pyd
import solders.account_decoder as _acct
import solders.errors as _err
import solders.rpc.config as _cfg
import solders.rpc.requests as _req
import solders.rpc.responses as _resp
from typing_extensions import Self

from .client import SolClient
from .errors import SolWsCloseError
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
from ..utils.pydantic import BaseModel

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


# Solders doesn't have this event...
class _SoldersUnsubResult(BaseModel):
    jsonrpc: Literal["2.0"]
    id: int
    result: bool


_SoldersWsMsg = Union[_resp.WebsocketMessage, _SoldersUnsubResult]
_SolWsObjKey = TypeVar("_SolWsObjKey")
_SolWsObj = TypeVar("_SolWsObj")


@dataclass(frozen=True)
class _SolWsObjInfo(Generic[_SolWsObjKey, _SolWsObj]):
    req_id: int | None
    sub_id: int | None
    key: _SolWsObjKey | None
    obj: _SolWsObj | None


class _SolWsSession(Generic[_SolWsObjKey, _SolWsObj]):
    _ObjInfo = _SolWsObjInfo[_SolWsObjKey, _SolWsObj]
    _empty_info: Final[_ObjInfo] = _SolWsObjInfo(None, None, None, None)

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

        self._update_future: asyncio.Future[Any] | None = None
        self._reconnect_future: asyncio.Future[Any] | None = None

    @property
    def sol_client(self) -> SolClient:
        return self._sol_client

    @property
    def is_connected(self) -> bool:
        return self._ws_session and (not self._ws_session.closed)

    @property
    def is_empty(self) -> bool:
        return not self._obj_dict

    async def connect(self) -> Self:
        if self.is_connected:
            return self

        ws_endpoint = HttpURL(self._ws_endpoint or self._cfg.random_sol_ws_url)

        # _LOG.debug("connecting to WebSocket %s...", ws_endpoint, extra=self._msg_filter)
        self._ws_session = await self._sol_client.session.ws_connect(ws_endpoint)
        # _LOG.debug("connected to WebSocket")
        return self

    async def disconnect(self) -> Self:
        if not self.is_connected:
            self._clear()
            return self

        # _LOG.debug("closing WebSocket connection...")
        ws_session, self._ws_session = self._ws_session, None

        self._clear()
        await ws_session.close()
        # _LOG.debug("closed WebSocket connection")
        return self

    async def reconnect(self) -> Self:
        await self.disconnect()
        return await self.connect()

    async def update(self, *, timeout_nsec: int = 1) -> None:
        if self._update_future:
            await self._update_future
            return

        try:
            self._update_future = asyncio.get_event_loop().create_future()
            await self._wait(timeout_nsec, time.monotonic_ns())

        finally:
            future, self._update_future = self._update_future, None
            if future:
                future.set_result(None)

    async def __aenter__(self) -> Self:
        return await self.connect()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> Self:
        await self.disconnect()
        if exc_val:
            raise
        return self

    def _get_next_id(self) -> int:
        return next(self._id)

    async def _ws_send_data(self, data: _SolWsSendData) -> None:
        if not self.is_connected:
            raise SolError("WebSocket is not connected")
        # _LOG.debug("TYPE %s, %s", type(data), str(data))
        await self._ws_session.send_str(data.to_json())

    async def _ws_receive_data(self, timeout_sec: float | None) -> Sequence[_SoldersWsMsg]:
        if not self._ws_session:
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
            # _LOG.debug("WebSocket closed while waiting for message")
            await self._on_close()
            return tuple()
        elif msg_type != _WsMsgType.TEXT:
            raise SolError(f"Unexpected WebSocket message type {msg_type}")

        try:
            return tuple(_resp.parse_websocket_message(msg.data))
        except _err.SerdeJSONError:
            try:
                # solders doesn't contain parser for this event type
                return tuple([_SoldersUnsubResult.from_json(msg.data)])
            except _pyd.ValidationError:
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
                    _LOG.warning("got error %s for %s", item.error, key)
                    self._on_sub_error(key, info.obj)
                else:
                    _LOG.warning("unknown request %s on error", item.id)
            elif isinstance(item, _SoldersSubResult):
                if key := self._req_dict.pop(item.id, None):
                    info = self._obj_dict.pop(key, self._empty_info)
                    assert not info.sub_id, f"subscription {info.sub_id} for {key} already exists?"
                    assert item.result not in self._sub_dict, f"subscription {item.result} for {key} already exists?"

                    self._sub_dict[item.result] = key
                    info = _SolWsObjInfo(key=key, obj=info.obj, req_id=item.id, sub_id=item.result)
                    self._obj_dict[key] = info
                    # _LOG.debug("got subscription %s for %s", item.result, key)
                else:
                    _LOG.warning("unknown request %s for result %s", item.id, item.result)
            elif isinstance(item, _SolWsSubNotif):
                if key := self._sub_dict.pop(item.subscription, None):
                    info = self._obj_dict.pop(key, self._empty_info)
                    assert info.req_id not in self._req_dict, f"request {info.req_id} for {key} still exists?"
                    # _LOG.debug("got notification %s", key)
                    self._on_sub_notif(info, item, now_nsec)
                else:
                    _LOG.warning("unknown subscription %s on notification", item.subscription)

    async def _sub_obj(self, key: _SolWsObjKey, obj: _SolWsObj | None, commit: SolCommit) -> None:
        if key in self._obj_dict:
            return

        req_id = self._get_next_id()
        info = _SolWsObjInfo(key=key, obj=obj, req_id=req_id, sub_id=None)
        self._req_dict[req_id] = key
        self._obj_dict[key] = info

        req = self._new_sub_request(info, commit)

        try:
            # _LOG.debug("subscribe %s on tx %s", sig_info.req_id, tx)
            await self._ws_send_data(req)
        except (BaseException,):
            # _LOG.error("ERROR subscribe %s", str(e), exc_info=e)
            self._obj_dict.pop(key, None)
            self._req_dict.pop(req_id, None)
            raise

    async def _unsub_obj(self, key: _SolWsObjKey) -> None:
        if not (info := self._obj_dict.pop(key, None)):
            return
        elif self._req_dict.pop(info.req_id, None):
            _LOG.warning("didn't receive subscription for %s", key)

        if self._sub_dict.pop(info.sub_id, None):
            req_id = self._get_next_id()
            req = self._new_unsub_request(req_id, info.sub_id)
            try:
                await self._ws_send_data(req)
            except (BaseException,):
                # _LOG.error("ERROR unsubscribe %s", str(e), exc_info=e)
                pass

    def _clear(self) -> None:
        self._sub_dict.clear()
        self._req_dict.clear()
        self._obj_dict.clear()

    async def _on_close(self) -> None:
        if self._reconnect_future:
            await self._reconnect_future
            return

        try:
            self._reconnect_future = asyncio.get_event_loop().create_future()
            await self._on_reconnect()
        finally:
            future, self._reconnect_future = self._reconnect_future, None
            if future:
                future.set_result(None)

    # fmt: off
    async def _on_reconnect(self) -> None: ...
    def _on_sub_error(self, key: _SolWsObjKey, obj: _SolWsObj) -> None: ...
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
        while self._obj_dict:
            now_nsec = time.monotonic_ns()
            if (wait_nsec := timeout_nsec - (now_nsec - start_time_nsec)) <= 0:
                return False
            await super()._wait(wait_nsec, now_nsec)
        return True

    async def _on_close(self) -> None:
        if self._obj_dict:
            raise SolWsCloseError(
                f"WebSocket closed while waiting for update; close code was {self._ws_session.close_code}"
            )

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
        super().__init__(*args, **kwargs)
        self._commit = commit
        self._force_update_nsec = update_nsec
        self._has_update_queue = has_update_queue
        self._recheck_queue: deque[SolWatchAccountSession._RecheckAcctInfo] = deque()
        self._chg_key_set: set[SolPubKey] = set()

    async def subscribe_account(self, addr: SolPubKey, *, init_account=False) -> None:
        if addr in self._obj_dict:
            return

        acct = await self._sol_client.get_account(addr, commit=self._commit) if init_account else None
        for retry in itertools.count():
            try:
                await self.connect()
                await self._sub_obj(addr, acct, self._commit)
                self._chg_key_set.add(addr)

                return
            except (BaseException,):
                if retry > 5:
                    raise

    async def unsubscribe_account(self, addr: SolPubKey) -> None:
        await self._unsub_obj(addr)
        self._chg_key_set.discard(addr)

    def get_account(self, addr: SolPubKey) -> SolAccountModel | None:
        return info.obj if (info := self._obj_dict.get(addr, None)) else None

    def pop_changed_key_list(self) -> Sequence[SolPubKey]:
        key_set, self._chg_key_set = self._chg_key_set, set()

        last_nsec = time.monotonic_ns() - self._force_update_nsec
        while self._recheck_queue and (self._recheck_queue[0].insert_nsec <= last_nsec):
            top = self._recheck_queue.popleft()
            if top.key in self._obj_dict:
                key_set.add(top.key)

        return tuple(key_set)

    async def _on_reconnect(self) -> None:
        acct_queue: list[_SolWsObjInfo] = list()
        for retry in itertools.count():
            acct_queue.extend(self._obj_dict.values())
            self._clear()

            try:
                await self.reconnect()

                while acct_queue:
                    info = acct_queue.pop()
                    await self._sub_obj(info.key, info.obj, self._commit)
                return

            except (BaseException,):
                if retry > 5:
                    raise

    def _on_sub_notif(self, info: _AcctInfo, data: _SoldersAcctNotif, now_nsec: int) -> None:
        acct = SolAccountModel.from_raw(info.key, data.result.value)
        info = _SolWsObjInfo(req_id=info.req_id, sub_id=info.sub_id, key=info.key, obj=acct)
        self._obj_dict[info.key] = info
        self._sub_dict[info.sub_id] = info.key

        if self._has_update_queue:
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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._data: _SoldersSlotInfo | None = None
        self._prev_root: int | None = None

    async def subscribe(
        self, *,
        init_start_slot = False,
        confirmed_slot = 0,
        finalized_slot = 0,
    ) -> None:
        if self._data:
            return

        if init_start_slot:
            confirmed_slot, finalized_slot = await asyncio.gather(*[
                self._sol_client.get_slot(SolCommit.Confirmed),
                self._sol_client.get_slot(SolCommit.Finalized),
            ])
        self._data = _SoldersSlotInfo(confirmed_slot, 0, finalized_slot)

        await self.connect()
        await self._sub_slot()

    async def update(self, *, timeout_nsec: int = int(2 * ONE_BLOCK_SEC * 1e9)) -> None:
        await self.subscribe()
        await super().update(timeout_nsec=timeout_nsec)

    def get_slot(self, commit: SolCommit) -> int:
        if commit == SolCommit.Confirmed:
            return self._data.parent
        elif commit == SolCommit.Finalized:
            return self._data.root
        assert False, f"unknown commit {commit}"

    @property
    def confirmed_slot(self) -> int:
        return self._data.parent

    @property
    def finalized_slot(self) -> int:
        return self._data.root

    async def _sub_slot(self) -> None:
        await self._sub_obj(1, None, SolCommit.Confirmed)

    def _new_sub_request(self, info: _SlotInfo, commit: SolCommit) -> _SolWsSendData:
        return _SoldersSubSlot(info.req_id)

    def _on_sub_notif(self, info: _SlotInfo, data: _SoldersSlotNotif, now_nsec: int) -> None:
        new_data = data.result
        if self._prev_root:
            self._data = _SoldersSlotInfo(new_data.slot, new_data.parent, self._prev_root)

        self._prev_root = new_data.root
        self._obj_dict[info.key] = info
        self._sub_dict[info.sub_id] = info.key

    async def _on_reconnect(self) -> None:
        self._clear()

        for retry in itertools.count():
            try:
                await self.reconnect()
                await self._sub_slot()
                return

            except (BaseException,):
                if retry > 5:
                    raise

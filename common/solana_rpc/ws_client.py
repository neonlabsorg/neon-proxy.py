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

_SoldersSubResult = _resp.SubscriptionResult
_SoldersSubError = _resp.SubscriptionError

_SoldersNotif = _resp.Notification
_SoldersTxSigNotif = _resp.SignatureNotification
_SoldersAcctNotif = _resp.AccountNotification
_SoldersSlotNotif = _resp.SlotNotification

_WsSession = _ws.ClientWebSocketResponse
_WsMsgType = _ws.WSMsgType

_SolWsSendData = Union[_SoldersSubTxSig, _SoldersUnsubTxSig, _SoldersSubAcct, _SoldersUnsubAcct]
_SolWsSubNotif = Union[_SoldersTxSigNotif, _SoldersAcctNotif]


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

    async def _wait(self, timeout_sec: float | None) -> None:
        item_list = await self._ws_receive_data(timeout_sec)
        now = time.monotonic_ns()
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
                    self._on_sub_notif(info, item, now)
                else:
                    _LOG.warning("unknown subscription %s on notification", item.subscription)

    async def _sub_obj(self, key: _SolWsObjKey, obj: _SolWsObj, commit: SolCommit) -> None:
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

    # fmt: off
    async def _on_close(self) -> None: ...
    def _on_sub_error(self, key: _SolWsObjKey, obj: _SolWsObj) -> None: ...
    def _on_sub_notif(self, info: _ObjInfo, data: _SolWsSubNotif, now: int) -> None: ...
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
        try:
            await self.connect()
            await asyncio.gather(*[self._sub_obj(tx.sig, tx, commit) for tx in tx_list])
            return await self._wait(timeout_sec)
        except BaseException as exc:
            _LOG.error("error on waiting statuses for txs", exc_info=exc)
            return False
        finally:
            await self.disconnect()

    async def _on_close(self) -> None:
        if not self._obj_dict:
            return

        raise SolWsCloseError(
            f"WebSocket closed while waiting for update; close code was {self._ws_session.close_code}"
        )

    async def _wait(self, timeout_sec: float) -> bool:
        start_time_sec = time.monotonic()
        # _LOG.debug("OBJ %s %s", len(self._obj_dict), timeout_sec)
        while self._obj_dict:
            if (wait_sec := timeout_sec - (time.monotonic() - start_time_sec)) <= 0:
                return False
            await super()._wait(wait_sec)
        return True

    def _new_sub_request(self, info: _TxInfo, commit: SolCommit) -> _SolWsSendData:
        cfg = _SoldersTxSigCfg(commit.to_rpc_commit())
        return _SoldersSubTxSig(info.key, cfg, info.req_id)

    def _new_unsub_request(self, req_id: int, sub_id: int) -> _SolWsSendData:
        return _SoldersUnsubTxSig(sub_id, req_id)


@dataclass(frozen=True)
class _RecheckAcctInfo:
    key: SolPubKey
    insert_nsec: int


class SolWatchAccountSession(_SolWsSession[SolPubKey, SolAccountModel]):
    _AcctInfo = _SolWsObjInfo[SolPubKey, SolAccountModel]

    def __init__(self, *args, **kwargs) -> None:
        commit = kwargs.pop("commit", SolCommit.Confirmed)
        update_nsec = int(kwargs.pop("force_check_sec", 0) * (10**9))
        has_update_queue = (update_nsec > 0) or kwargs.pop("has_update_queue", False)
        super().__init__(*args, **kwargs)
        self._commit = commit
        self._force_update_nsec = update_nsec
        self._has_update_queue = has_update_queue
        self._reconnect_future: asyncio.Future[Any] | None = None
        self._update_future: asyncio.Future[Any] | None = None
        self._recheck_queue: deque[_RecheckAcctInfo] = deque()
        self._chg_key_set: set[SolPubKey] = set()

    async def update(self, *, timeout_sec: float = 0.0001) -> None:
        if self._update_future:
            await self._update_future
            return

        try:
            self._update_future = asyncio.get_event_loop().create_future()
            await self._wait(timeout_sec)

        finally:
            future, self._update_future = self._update_future, None
            if future:
                future.set_result(None)

    async def subscribe_account(self, addr: SolPubKey) -> None:
        if addr in self._obj_dict:
            return

        acct = await self._sol_client.get_account(addr, commit=self._commit)
        await self._sub_obj(addr, acct, self._commit)
        self._chg_key_set.add(addr)

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

    async def _on_close(self) -> None:
        if self._reconnect_future:
            await self._reconnect_future
            return

        try:
            self._reconnect_future = asyncio.get_event_loop().create_future()

            acct_list = tuple([info.obj for info in self._obj_dict.values()])
            self._clear()

            await self.disconnect()
            await self.connect()

            if acct_list:
                await asyncio.gather(*[self._sub_obj(acct.address, acct, self._commit) for acct in acct_list])
        finally:
            future, self._reconnect_future = self._reconnect_future, None
            if future:
                future.set_result(None)

    def _on_sub_notif(self, info: _AcctInfo, data: _SoldersAcctNotif, now: int) -> None:
        acct = SolAccountModel.from_raw(info.key, data.result.value)
        info = _SolWsObjInfo(req_id=info.req_id, sub_id=info.sub_id, key=info.key, obj=acct)
        self._obj_dict[info.key] = info
        self._sub_dict[info.sub_id] = info.key

        if self._has_update_queue:
            self._chg_key_set.add(info.key)
            self._recheck_queue.append(_RecheckAcctInfo(info.key, now))

    def _new_sub_request(self, info: _AcctInfo, commit: SolCommit) -> _SolWsSendData:
        cfg = _SoldersAcctCfg(encoding=_SoldersAcctEnc.Base64, commitment=commit.to_rpc_commit())
        return _SoldersSubAcct(info.key, cfg, info.req_id)

    def _new_unsub_request(self, req_id: int, sub_id: int) -> _SolWsSendData:
        return _SoldersUnsubAcct(sub_id, req_id)

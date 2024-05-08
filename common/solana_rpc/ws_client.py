from __future__ import annotations

import asyncio
import itertools
import logging
import time
from dataclasses import dataclass
from typing import Union, ClassVar, Sequence, Literal

import aiohttp as _ws
import pydantic
import solders.rpc.config as _cfg
import solders.rpc.requests as _req
import solders.rpc.responses as _resp
import solders.errors as _err
from typing_extensions import Self

from .client import SolClient
from .errors import SolWsCloseError
from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..http.utils import HttpURL, HttpStrOrURL
from ..solana.commit_level import SolCommit
from ..solana.errors import SolError
from ..solana.signature import SolTxSig
from ..solana.transaction import SolTx
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)

_SoldersTxSigCfg = _cfg.RpcSignatureSubscribeConfig
_SoldersSubTxSig = _req.SignatureSubscribe
_SoldersUnsubTxSig = _req.SignatureUnsubscribe

_SoldersSubResult = _resp.SubscriptionResult
_SoldersSubError = _resp.SubscriptionError

_SoldersNotif = _resp.Notification
_SoldersTxSigNotif = _resp.SignatureNotification
_SoldersAcctNotif = _resp.AccountNotification
_SoldersSlotNotif = _resp.SlotNotification

_WsSession = _ws.ClientWebSocketResponse
_WsMsgType = _ws.WSMsgType

_WsSendData = Union[_SoldersSubTxSig, _SoldersUnsubTxSig]


class _SoldersUnsubResult(BaseModel):
    jsonrpc: Literal["2.0"]
    id: int
    result: bool


_SoldersWsMsg = Union[_resp.WebsocketMessage, _SoldersUnsubResult]


class _SolWsSession:
    def __init__(self, cfg: Config, sol_client: SolClient, *, ws_endpoint: HttpStrOrURL | None = None) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._ws_endpoint = ws_endpoint
        self._msg_filter = LogMsgFilter(cfg)

        self._id = itertools.count()
        self._ws_session: _WsSession | None = None

    @property
    def sol_client(self) -> SolClient:
        return self._sol_client

    def _get_next_id(self) -> int:
        return next(self._id)

    @property
    def is_connected(self):
        return self._ws_session and (not self._ws_session.closed)

    async def connect(self) -> Self:
        if self.is_connected:
            return self

        ws_endpoint = HttpURL(self._ws_endpoint or self._cfg.random_sol_ws_url)

        _LOG.debug("connecting to WebSocket %s...", ws_endpoint, extra=self._msg_filter)
        self._ws_session = await self._sol_client.session.ws_connect(ws_endpoint)
        _LOG.debug("connected to WebSocket")
        return self

    async def disconnect(self) -> Self:
        if not self.is_connected:
            await self._on_close()
            return self

        _LOG.debug("closing WebSocket connection...")
        ws_session, self._ws_session = self._ws_session, None

        await self._on_close()
        await ws_session.close()
        _LOG.debug("closed WebSocket connection")

    async def _ws_send_data(self, data: _WsSendData) -> None:
        if not self.is_connected:
            raise SolError("WebSocket is not connected")
        await self._ws_session.send_str(data.to_json())

    async def _ws_receive_data(self, timeout_sec: float) -> tuple[_SoldersWsMsg, ...]:
        if not self._ws_session:
            raise SolError("WebSocket is not connected")

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
            raise SolWsCloseError(
                f"WebSocket closed while waiting for update; close code was {self._ws_session.close_code}"
            )
        elif msg_type != _WsMsgType.TEXT:
            raise SolError(f"Unexpected WebSocket message type {msg_type}")

        try:
            return tuple(_resp.parse_websocket_message(msg.data))
        except _err.SerdeJSONError:
            try:
                # solders doesn't contain parser for this event type
                return tuple([_SoldersUnsubResult.from_json(msg.data)])
            except pydantic.ValidationError:
                _LOG.warning("unexpected error on parsing websocket message: %s", msg.data)
        except (BaseException,):
            _LOG.warning("unexpected error on parsing websocket message: %s", msg.data)
        return tuple()

    async def _on_close(self) -> None:
        pass


@dataclass(frozen=True)
class _TxSigInfo:
    tx: SolTx | None
    req_id: int | None
    sub_id: int | None


class SolWatchTxSession(_SolWsSession):
    _empty_sig_info: ClassVar[_TxSigInfo] = _TxSigInfo(None, None, None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._req_dict: dict[int, SolTxSig] = dict()
        self._sub_dict: dict[int, SolTxSig] = dict()
        self._tx_dict: dict[SolTxSig, _TxSigInfo] = dict()

    async def wait_for_tx_receipt_list(
        self,
        tx_list: Sequence[SolTx],
        commit: SolCommit,
        timeout_sec: float,
    ) -> bool:
        try:
            await self.connect()
            await asyncio.gather(*[self._subscribe_tx(tx, commit) for tx in tx_list])

            return await self._wait(timeout_sec)
        except BaseException as exc:
            _LOG.error("error on waiting statuses for txs", exc_info=exc)
            return False
        finally:
            await asyncio.gather(*[self._unsubscribe_tx(tx) for tx in tx_list])

    async def _wait(self, timeout_sec: float) -> bool:
        start_time_sec = time.monotonic()
        while self._tx_dict:
            if (wait_sec := timeout_sec - (time.monotonic() - start_time_sec)) <= 0:
                return False

            item_list = await self._ws_receive_data(wait_sec)
            for item in item_list:
                if isinstance(item, _SoldersSubError):
                    if tx_sig := self._req_dict.pop(item.id, None):
                        sig_info = self._tx_dict.pop(tx_sig, self._empty_sig_info)
                        assert (
                            sig_info.sub_id not in self._sub_dict
                        ), f"subscription {sig_info.sub_id} for {sig_info.tx} already exists?"
                        _LOG.warning("got error %s for tx %s", item.error, sig_info.tx)
                    else:
                        _LOG.warning("unknown request %s on error", item.id)
                elif isinstance(item, _SoldersSubResult):
                    if tx_sig := self._req_dict.pop(item.id, None):
                        sig_info = self._tx_dict.pop(tx_sig, self._empty_sig_info)
                        assert not sig_info.sub_id, f"subscription {sig_info.sub_id} for {sig_info.tx} already exists?"
                        assert (
                            item.result not in self._sub_dict
                        ), f"subscription {item.result} for {sig_info.tx} already exists?"

                        self._sub_dict[item.result] = tx_sig
                        self._tx_dict[tx_sig] = _TxSigInfo(tx=sig_info.tx, req_id=item.id, sub_id=item.result)
                        # _LOG.debug("got subscription %s for tx %s", item.result, tx_sig)
                    else:
                        _LOG.warning("unknown request %s for result %s", item.id, item.result)
                elif isinstance(item, _SoldersTxSigNotif):
                    if tx_sig := self._sub_dict.pop(item.subscription, None):
                        sig_info = self._tx_dict.pop(tx_sig, self._empty_sig_info)
                        assert (
                            sig_info.req_id not in self._req_dict
                        ), f"request {sig_info.req_id} for {sig_info.tx} still exists?"
                        _LOG.debug("tx %s is committed", sig_info.tx)
                    else:
                        _LOG.warning("unknown subscription %s on notification", item.subscription)
        return True

    async def _subscribe_tx(self, tx: SolTx, commit: SolCommit) -> None:
        if tx.sig in self._tx_dict:
            return

        sig_info = _TxSigInfo(tx=tx, req_id=self._get_next_id(), sub_id=None)
        self._req_dict[sig_info.req_id] = tx.sig
        self._tx_dict[tx.sig] = sig_info

        cfg = _SoldersTxSigCfg(commit.to_rpc_commit())
        req = _SoldersSubTxSig(tx.sig, cfg, sig_info.req_id)

        try:
            # _LOG.debug("subscribe %s on tx %s", sig_info.req_id, tx)
            await self._ws_send_data(req)
        except (BaseException,):
            self._tx_dict.pop(tx.sig, None)
            self._req_dict.pop(sig_info.req_id, None)
            raise

    async def _unsubscribe_tx(self, tx: SolTx) -> None:
        if not (sig_info := self._tx_dict.pop(tx.sig, None)):
            return
        elif self._req_dict.pop(sig_info.req_id, None):
            _LOG.warning("didn't receive subscription for tx %s", tx)

        if self._sub_dict.pop(sig_info.sub_id, None):
            _LOG.debug("unsubscribe tx %s ", tx)

            req = _SoldersUnsubTxSig(sig_info.sub_id, self._get_next_id())
            try:
                await self._ws_send_data(req)
            except (BaseException,):
                pass

from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .server_abc import MempoolApi
from .transaction_executor import MpTxExecutor
from ..base.mp_api import (
    MpTxCntRequest,
    MpTxCntResp,
    MpTxRequest,
    MpTxResp,
    MpGetTxByHashRequest,
    MpGetTxResp,
    MpGetTxBySenderNonceRequest,
    MpRequest,
    MpTxPoolContentResp,
)


class MpTxApi(MempoolApi):
    name: ClassVar[str] = "Mempool::Transaction"

    @cached_property
    def _tx_executor(self) -> MpTxExecutor:
        return self._server._tx_executor  # noqa

    @MempoolApi.method(name="getPendingTransactionCounter")
    def get_pending_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp:
        with logging_context(ctx=request.ctx_id):
            tx_cnt = self._tx_executor.get_pending_tx_cnt(request.sender)
            return MpTxCntResp(tx_cnt=tx_cnt)

    @MempoolApi.method(name="getMempoolTransactionCounter")
    def get_mempool_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp:
        with logging_context(ctx=request.ctx_id):
            tx_cnt = self._tx_executor.get_last_tx_cnt(request.sender)
            return MpTxCntResp(tx_cnt=tx_cnt)

    @MempoolApi.method(name="sendRawTransaction")
    async def send_raw_transaction(self, request: MpTxRequest) -> MpTxResp:
        with logging_context(ctx=request.ctx_id, tx=request.tx.tx_id):
            return await self._tx_executor.schedule_tx_request(request.tx, request.state_tx_cnt)

    @MempoolApi.method(name="getPendingTransactionByHash")
    def get_tx_by_hash(self, request: MpGetTxByHashRequest) -> MpGetTxResp:
        with logging_context(ctx=request.ctx_id):
            tx = self._tx_executor.get_tx_by_hash(request.neon_tx_hash)
            return MpGetTxResp(tx=tx)

    @MempoolApi.method(name="getPendingTransactionBySenderNonce")
    def get_tx_by_sender_nonce(self, request: MpGetTxBySenderNonceRequest) -> MpGetTxResp:
        with logging_context(ctx=request.ctx_id):
            tx = self._tx_executor.get_tx_by_sender_nonce(request.sender, request.tx_nonce)
            return MpGetTxResp(tx=tx)

    @MempoolApi.method(name="getMempoolContent")
    async def _get_content(self, request: MpRequest) -> MpTxPoolContentResp:
        with logging_context(ctx=request.ctx_id):
            return self._tx_executor.get_content(request.chain_id)

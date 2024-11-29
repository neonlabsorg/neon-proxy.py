from typing import ClassVar

from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .server_abc import MempoolApi
from .transaction_executor import MpTxExecutor
from ..base.ex_api import (
    ExecTxDoneRequest,
    ExecTxDoneResp,
    ExecTxDoneStuckRequest,
    ExecTxDoneStuckResp,
    ExecTxNotifyStatusRequest,
    ExecTxNotifyStatusResp,
)


class MpTxExecStatusApi(MempoolApi):
    name: ClassVar[str] = "Mempool::TransactionExecutionStatus"

    @cached_property
    def _tx_executor(self) -> MpTxExecutor:
        return self._server._tx_executor  # noqa

    @MempoolApi.method(name="notifyExecuteTransactionStatus")
    def notify_exec_tx_status(self, request: ExecTxNotifyStatusRequest) -> ExecTxNotifyStatusResp:
        with logging_context(**request.req_id):
            res = self._tx_executor.notify_exec_tx_status(request.base_tx_hash, request.neon_tx_hash, request.exec_pct)
            return ExecTxNotifyStatusResp(result=res)

    @MempoolApi.method(name="doneExecuteTransaction")
    def done_exec_tx(self, request: ExecTxDoneRequest) -> ExecTxDoneResp:
        with logging_context(**request.req_id):
            res = self._tx_executor.done_exec_tx(request)
            return ExecTxDoneResp(result=res)

    @MempoolApi.method(name="doneCompleteStuckTransaction")
    def done_complete_stuck_tx(self, request: ExecTxDoneStuckRequest) -> ExecTxDoneStuckResp:
        with logging_context(**request.req_id):
            res = self._tx_executor.done_complete_stuck_tx(request)
            return ExecTxDoneStuckResp(result=res)

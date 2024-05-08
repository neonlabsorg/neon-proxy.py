from typing import Union

import solders.instruction as _ix
import solders.rpc.errors as _err
import solders.rpc.responses as _resp
import solders.transaction_status as _tx

SolRpcTxInfo = _tx.EncodedTransactionWithStatusMeta
SolRpcTxSlotInfo = _tx.EncodedConfirmedTransactionWithStatusMeta
SolRpcTxMetaInfo = _tx.UiTransactionStatusMeta
SolRpcTxIxInfo = Union[_ix.CompiledInstruction, _tx.UiCompiledInstruction]
SolRpcTxInnerIxList = _tx.UiInnerInstructions

SolRpcErrorInfo = _resp.RPCError
SolRpcExtErrorInfo = Union[
    _err.ParseErrorMessage,
    _err.InvalidRequestMessage,
    _err.MethodNotFoundMessage,
    _err.InvalidParamsMessage,
    _err.InternalErrorMessage,
]
SolRpcTxErrorInfo = _tx.TransactionErrorType
SolRpcTxFieldErrorCode = _tx.TransactionErrorFieldless
SolRpcTxIxErrorInfo = _tx.InstructionErrorType
SolRpcTxIxFieldErrorCode = _tx.InstructionErrorFieldless
SolRpcSendTxErrorInfo = _resp.RpcSimulateTransactionResult
SolRpcNodeUnhealthyErrorInfo = _err.NodeUnhealthy
SolRpcInvalidParamErrorInfo = _err.InvalidParamsMessage

SolRpcTxReceiptInfo = Union[SolRpcTxSlotInfo, SolRpcSendTxErrorInfo, SolRpcNodeUnhealthyErrorInfo]

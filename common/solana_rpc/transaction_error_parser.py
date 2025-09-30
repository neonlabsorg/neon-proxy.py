from __future__ import annotations

import logging
import re
from typing import Sequence, Final

from ..neon.cancel_error import CancelErrorSource, CancelErrorData, SolCancelErrorCode
from ..neon_rpc.api import EmulSolTxIxMetaModel
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcTxIxErrorInfo,
    SolRpcTxIxFieldErrorCode,
    SolRpcTxErrorInfo,
    SolRpcTxFieldErrorCode,
    SolRpcSendTxErrorInfo,
    SolRpcNodeUnhealthyErrorInfo,
    SolRpcTxReceiptInfo,
)
from ..utils.cached import cached_method, cached_property

_LOG = logging.getLogger(__name__)


class SolTxErrorParser:
    _log_truncated_msg: Final[str] = "Log truncated"
    _cb_exceeded_msg: Final[str] = "exceeded CUs meter at BPF instruction"
    _cb_exceeded_msg_v2: Final[str] = "Computational budget exceeded"

    # fmt: off
    _alt_tx_error_list: Final[Sequence[SolRpcTxFieldErrorCode]] = tuple([
        SolRpcTxFieldErrorCode.AddressLookupTableNotFound,
        SolRpcTxFieldErrorCode.InvalidAddressLookupTableOwner,
        SolRpcTxFieldErrorCode.InvalidAddressLookupTableData,
        SolRpcTxFieldErrorCode.InvalidAddressLookupTableIndex,
    ])
    _alt_ix_error_list: Final[Sequence[SolRpcTxFieldErrorCode]] = tuple([
        SolRpcTxIxFieldErrorCode.InvalidInstructionData,
        SolRpcTxIxFieldErrorCode.InvalidAccountOwner,
        SolRpcTxIxFieldErrorCode.InvalidArgument,
    ])
    _writable_error_list: Final[Sequence[SolRpcTxFieldErrorCode]] = tuple([
        SolRpcTxIxFieldErrorCode.PrivilegeEscalation,
        SolRpcTxIxFieldErrorCode.ReadonlyDataModified,
        SolRpcTxIxFieldErrorCode.ReadonlyLamportChange,
    ])
    # fmt: on
    _alt_fail_msg: Final[str] = "Program AddressLookupTab1e1111111111111111111111111 failed: "
    _prog_fail_re: Final[re.Pattern] = re.compile(r"Program (\w+) failed: (.*)")
    _custom_err_re: Final[re.Pattern] = re.compile(r"custom program error: 0x([0-9A-Fa-f]+)")

    def __init__(self, tx: SolTx | None, receipt: SolRpcTxReceiptInfo | EmulSolTxIxMetaModel | None) -> None:
        self._tx = tx
        self._receipt = receipt

    @cached_method
    def get_error(self) -> CancelErrorData | None:
        log_list = self._get_log_list()
        for log_rec in log_list:
            if failed_match := self._prog_fail_re.match(log_rec):
                addr = SolPubKey.from_string(failed_match.group(1))
                msg = failed_match.group(2)

                code_match = self._custom_err_re.match(msg)
                code = int(code_match.group(1), 16) if code_match else SolCancelErrorCode.Unknown
                return CancelErrorData(CancelErrorSource.Solana, addr, code, msg)

        if msg := self._get_error_msg():
            _LOG.warning("fail on get error from meta %s", self._receipt)
            return CancelErrorData.from_str(msg)
        return None

    @cached_method
    def check_if_alt_error(self) -> bool:
        if not (tx_error := self._get_tx_error()):
            return False
        elif tx_error in self._alt_tx_error_list:
            return True
        elif tx_error not in self._alt_ix_error_list:
            return False

        log_list = self._get_log_list()
        for log in log_list:
            if log.startswith(self._alt_fail_msg):
                return True
        return False

    @cached_method
    def check_if_cb_exceeded(self) -> bool:
        if self._get_tx_error() == SolRpcTxIxFieldErrorCode.ComputationalBudgetExceeded:
            return True

        log_list = self._get_log_list()
        for log_rec in log_list:
            if log_rec == self._log_truncated_msg:
                return True
            elif log_rec.find(self._cb_exceeded_msg) != -1:
                return True
            elif log_rec.find(self._cb_exceeded_msg_v2) != -1:
                return True
        return False

    @cached_method
    def check_if_unsupported_prog(self) -> bool:
        return self._get_tx_error() == SolRpcTxIxFieldErrorCode.UnsupportedProgramId

    @cached_property
    def cu_consumed(self) -> int | None:
        if isinstance(self._receipt, EmulSolTxIxMetaModel):
            return self._receipt.cu_consumed
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            return getattr(self._receipt, "units_consumed", None)
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            if meta := getattr(self._receipt.transaction, "meta", None):
                return getattr(meta, "compute_units_consumed", None)
        return None

    @cached_method
    def check_if_blockhash_notfound(self) -> bool:
        if self._receipt is None:
            return True
        return self._get_tx_error() == SolRpcTxFieldErrorCode.BlockhashNotFound

    @cached_method
    def check_if_preprocessed_error(self) -> bool:
        return isinstance(self._receipt, SolRpcSendTxErrorInfo)

    @cached_method
    def check_if_writable_error(self) -> bool:
        return self._get_tx_error() in self._writable_error_list

    @cached_method
    def get_num_slots_behind(self) -> int | None:
        if isinstance(self._receipt, SolRpcNodeUnhealthyErrorInfo):
            return self._receipt.num_slots_behind
        return None

    def _get_tx_error(self) -> SolRpcTxErrorInfo | SolRpcTxIxFieldErrorCode | None:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            if isinstance(self._receipt.err, SolRpcTxFieldErrorCode):
                return self._receipt.err
            elif isinstance(self._receipt.err, SolRpcTxIxErrorInfo):
                return self._receipt.err.err
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            if isinstance(self._receipt.transaction.meta.err, SolRpcTxErrorInfo):
                return self._receipt.transaction.meta.err
            elif isinstance(self._receipt.transaction.meta.err, SolRpcTxIxErrorInfo):
                return self._receipt.transaction.meta.err.err
        return None

    @cached_method
    def _get_log_list(self) -> Sequence[str]:
        if isinstance(self._receipt, EmulSolTxIxMetaModel):
            return self._receipt.log_list
        elif isinstance(self._receipt, SolRpcSendTxErrorInfo):
            return tuple(self._receipt.logs or list())
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            return tuple(self._receipt.transaction.meta.log_messages or list())
        return tuple()

    @cached_method
    def _get_error_msg(self) -> str | None:
        if isinstance(self._receipt, EmulSolTxIxMetaModel):
            if self._receipt.error:
                return str(self._receipt.error)
        elif isinstance(self._receipt, (SolRpcSendTxErrorInfo, SolRpcNodeUnhealthyErrorInfo)):
            return str(self._receipt.err)
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            if self._receipt.transaction.meta.err:
                return str(self._receipt.transaction.meta.err)
        return None

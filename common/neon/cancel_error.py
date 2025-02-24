from __future__ import annotations

import dataclasses
import enum
import logging
from typing import ClassVar

from .evm_log_decoder import NeonTxErrorLogInfo
from ..utils.cached import cached_method

_LOG = logging.getLogger(__name__)


class CancelErrorSource(enum.IntEnum):
    NeonProxy = enum.auto()
    NeonEVM = enum.auto()
    Solana = enum.auto()
    Unknown = 255


class NeonProxyCancelErrorCode(enum.IntEnum):
    Unknown = enum.auto()
    Manual = enum.auto()
    NoMoreRetriesError = enum.auto()
    WriteableError = enum.auto()
    CbExceedError = enum.auto()


class SolCancelErrorCode(enum.IntEnum):
    Unknown = enum.auto()
    Custom = enum.auto()


@dataclasses.dataclass(frozen=True)
class CancelErrorData:
    source: CancelErrorSource
    code: int
    message: str

    _default: ClassVar[CancelErrorData | None] = None
    _skipped: ClassVar[CancelErrorData | None] = None

    @classmethod
    def default(cls) -> CancelErrorData:
        if not cls._default:
            cls._default = cls(CancelErrorSource.Unknown, 0, "")
        return cls._default

    @classmethod
    def skipped(cls) -> CancelErrorData:
        if not cls._skipped:
            cls._skipped = cls(CancelErrorSource.NeonEVM, NeonTxErrorLogInfo.ErrorCode.Custom, "Skipped")
        return cls._skipped

    @classmethod
    def from_bytes(cls, data: bytes) -> CancelErrorData:
        try:
            raw_source, raw_code, raw_len, raw_msg = data[0:1], data[1:3], data[3:5], data[5:]

            source = CancelErrorSource(int.from_bytes(raw_source, "little"))
            code = int.from_bytes(raw_code, "little")
            msg_len = int.from_bytes(raw_len, "little")
            msg = raw_msg[:msg_len].decode("utf-8")
            return cls(source, code, msg)
        except (IndexError, ValueError):
            _LOG.warning("failed to parse CancelErrorData: %s", data.hex())
            return cls.default()

    @cached_method
    def to_bytes(self) -> bytes:
        err_data = self.message.encode("utf-8")
        # fmt: off
        return b"".join([
            int(self.source).to_bytes(1, "little"),
            self.code.to_bytes(2, "little"),
            len(err_data).to_bytes(2, "little"),
            err_data,
        ])
        # fmt: on

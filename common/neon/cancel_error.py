from __future__ import annotations

import dataclasses
import enum
import logging
from typing import ClassVar, Final, Self

from .evm_log_decoder import NeonTxErrorLogInfo
from .neon_program import NeonProg
from ..solana.pubkey import SolPubKey
from ..utils.cached import cached_method

_LOG = logging.getLogger(__name__)


class CancelErrorSource(enum.IntEnum):
    NeonProxy = enum.auto()
    NeonEVM = enum.auto()
    Solana = enum.auto()
    Unknown = 0x44


class NeonProxyCancelErrorCode(enum.IntEnum):
    Unknown = enum.auto()
    Manual = enum.auto()
    NoMoreRetriesError = enum.auto()
    WriteableError = enum.auto()
    CbExceedError = enum.auto()


class SolCancelErrorCode(enum.IntEnum):
    Unknown = 0


@dataclasses.dataclass(frozen=True)
class CancelErrorData:
    source: CancelErrorSource
    address: SolPubKey
    code: int
    message: str

    _version: Final[int] = 0x45
    _default: ClassVar[CancelErrorData | None] = None
    _skipped: ClassVar[CancelErrorData | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(CancelErrorSource.Solana, SolPubKey.default(), SolCancelErrorCode.Unknown, "unknown")
        return cls._default

    @classmethod
    def skipped(cls) -> Self:
        if not cls._skipped:
            cls._skipped = cls(CancelErrorSource.NeonEVM, NeonProg.ID, NeonTxErrorLogInfo.ErrorCode.Custom, "Skipped")
        return cls._skipped

    @classmethod
    def from_str(cls, message: str) -> Self:
        return cls(CancelErrorSource.Solana, SolPubKey.default(), SolCancelErrorCode.Unknown, message)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        try:
            if (version := int(data[0])) != cls._version:
                _LOG.warning("wrong CancelErrorData version: %s", version)
                return cls.default()

            data = data[1:]
            raw_source, raw_addr, raw_code, raw_len, raw_msg = data[0:1], data[1:33], data[33:35], data[35:37], data[37:]

            source = CancelErrorSource(int.from_bytes(raw_source, "little"))
            code = int.from_bytes(raw_code, "little")
            addr = SolPubKey.from_bytes(raw_addr)
            msg_len = int.from_bytes(raw_len, "little")
            msg = raw_msg[:msg_len].decode("utf-8")
            return cls(source, addr, code, msg)
        except (IndexError, ValueError):
            _LOG.warning("failed to parse CancelErrorData: %s", data.hex())
            return cls.default()

    @cached_method
    def to_bytes(self) -> bytes:
        addr = self.address.to_bytes()
        err_msg = self.message.encode("utf-8")
        # fmt: off
        return b"".join([
            self._version.to_bytes(1, "little"),
            int(self.source).to_bytes(1, "little"),
            addr,
            self.code.to_bytes(2, "little"),
            len(err_msg).to_bytes(2, "little"),
            err_msg,
        ])
        # fmt: on

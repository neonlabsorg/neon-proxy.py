from __future__ import annotations

import dataclasses
import enum
from typing import ClassVar

from common.utils.cached import cached_method


class CancelErrorSource(enum.IntEnum):
    Proxy = enum.auto()
    Neon = enum.auto()
    Solana = enum.auto()


class ProxyCancelErrorCode(enum.IntEnum):
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

    @classmethod
    def default(cls) -> CancelErrorData:
        if not cls._default:
            cls._default = cls(CancelErrorSource.Proxy, ProxyCancelErrorCode.Unknown, "Unknown")
        return cls._default

    @cached_method
    def to_bytes(self) -> bytes:
        err_data = self.message.encode("utf-8")
        return b"".join(
            [
                int(self.source).to_bytes(1, "little"),
                self.code.to_bytes(2, "little"),
                len(err_data).to_bytes(2, "little"),
                err_data,
            ]
        )

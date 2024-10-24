from __future__ import annotations

import logging
import re
import base64
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterator, Final, ClassVar

from typing_extensions import Self

from .pubkey import SolPubKey
from .transaction import SolTxMessageInfo
from .transaction_meta import (
    SolRpcTxMetaInfo,
    SolRpcTxIxInfo,
    SolRpcTxInnerIxList,
    SolRpcSendTxErrorInfo,
)
from ..utils.cached import cached_method
from ..utils.format import str_fmt_object

_LOG = logging.getLogger(__name__)


class SolTxLogTreeError(RuntimeError):
    def __init__(self, prog_id: SolPubKey, level: int) -> None:
        super().__init__(prog_id, level)
        self._prog_id = prog_id
        self._level = level

    def __str__(self) -> str:
        return f"Failed to find instruction for log record: {self._prog_id} [{self._level}]"


@dataclass(frozen=True)
class SolTxIxLogInfo:
    class Status(IntEnum):
        Unknown = 0
        Success = 1
        Failed = 2

    prog_id: SolPubKey
    level: int
    status: Status

    cu_limit: int
    used_cu_limit: int

    error: str | None

    log_list: tuple[str | SolTxIxLogInfo, ...]
    inner_log_list: tuple[SolTxIxLogInfo, ...]

    # private:
    _default: ClassVar[SolTxIxLogInfo | None] = None

    @classmethod
    def new_unknown(cls, prog_id=SolPubKey.default(), level=0) -> Self:
        ret_def = (prog_id, level) == (SolPubKey.default(), 0)
        if ret_def and (cls._default is not None):
            return cls._default

        self = cls(
            prog_id=prog_id,
            level=level,
            status=cls.Status.Unknown,
            cu_limit=0,
            used_cu_limit=0,
            error=None,
            log_list=tuple(),
            inner_log_list=tuple(),
        )

        if ret_def:
            cls._default = self
        return self

    @property
    def is_success(self) -> bool:
        return self.status == self.Status.Success

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    def log_msg_list(self) -> tuple[str, ...]:
        return tuple(filter(lambda log_rec: isinstance(log_rec, str), self.log_list))


@dataclass(frozen=True)
class SolTxLogTreeInfo:
    log_list: tuple[SolTxIxLogInfo, ...]


class SolTxLogTreeDecoder:
    _prog_log: Final[str] = "Program log: "
    _prog_data: Final[str] = "Program data: "

    @classmethod
    def decode(
        cls,
        rpc_message: SolTxMessageInfo,
        rpc_meta: SolRpcSendTxErrorInfo | SolRpcTxMetaInfo,
        account_key_list: tuple[SolPubKey, ...],
    ) -> SolTxLogTreeInfo:
        ctx = _SolLogDecoderCtx.from_raw(rpc_message, rpc_meta, account_key_list)
        root_log = _SolTxIxLogDraft.default()

        cls._decode(root_log, ctx)
        return root_log.to_clean_tree()

    @classmethod
    def _decode(cls, log: _SolTxIxLogDraft, ctx: _SolLogDecoderCtx) -> None:
        while msg := ctx.next_msg():
            if msg.startswith(cls._prog_log):
                pass
            elif msg.startswith(cls._prog_data):
                log.log_list.append(msg + str(len(msg)))
            elif cls._decode_invoke(log, msg, ctx):
                continue
            elif _SolSuccessLogDecoder.decode(log, msg):
                return
            elif _SolFailedLogDecoder.decode(log, msg):
                return
            elif _SolCuLogDecoder.decode(log, msg):
                continue
            log.log_list.append(msg)

    @classmethod
    def _decode_invoke(cls, log: _SolTxIxLogDraft, msg: str, ctx: _SolLogDecoderCtx) -> bool:
        inner_log = _SolInvokeLogDecoder.decode(msg)
        if inner_log is None:
            return False

        cls._add_missed_logs(log, inner_log, ctx)
        cls._decode(inner_log, ctx)

        clean_inner_log = inner_log.to_clean_copy()
        log.log_list.append(clean_inner_log)
        log.inner_log_list.append(clean_inner_log)

        log.inner_log_list.extend(inner_log.inner_log_list)
        return True

    @classmethod
    def _add_missed_logs(cls, log: _SolTxIxLogDraft, inner_log: _SolTxIxLogDraft, ctx: _SolLogDecoderCtx) -> None:
        while True:
            prog_id, level = ctx.next_prog_lvl(inner_log.level)
            if prog_id.is_empty:
                return
            elif (prog_id, level) == (inner_log.prog_id, inner_log.level):
                return

            missed_log = SolTxIxLogInfo.new_unknown(prog_id, level + 1)
            log.log_list.append(missed_log)
            log.inner_log_list.append(missed_log)


@dataclass
class _SolLogDecoderCtx:
    @classmethod
    def from_raw(
        cls,
        rpc_message: SolTxMessageInfo,
        rpc_meta: SolRpcSendTxErrorInfo | SolRpcTxMetaInfo,
        account_key_list: tuple[SolPubKey, ...],
    ) -> Self:
        inner_ix_list = getattr(rpc_meta, "inner_instructions", tuple())
        inner_ix_list_iter = iter(inner_ix_list) if inner_ix_list else None
        inner_ix_list = next(inner_ix_list_iter) if inner_ix_list_iter else None

        log_msg_list = rpc_meta.log_messages if isinstance(rpc_meta, SolRpcTxMetaInfo) else rpc_meta.logs

        return cls(
            _acct_list=account_key_list,
            _msg_iter=iter(log_msg_list),
            _ix_iter=iter(enumerate(rpc_message.instructions)),
            _inner_ix_list_iter=inner_ix_list_iter,
            _inner_ix_list=inner_ix_list,
            _inner_ix_iter=None,
        )

    def next_msg(self) -> str | None:
        return next(self._msg_iter, None)

    def next_prog_lvl(self, base_level: int) -> tuple[SolPubKey, int]:
        if base_level == 1:
            if not (ix := self._next_ix()):
                return SolPubKey.default(), 1
            return self._acct_list[ix.program_id_index], 1

        if not (ix := self._next_inner_ix()):
            return SolPubKey.default(), base_level
        return self._acct_list[ix.program_id_index], getattr(ix, "stack_height", base_level)

    # protected:
    _acct_list: tuple[SolPubKey, ...]
    _msg_iter: Iterator[str] | None
    _ix_iter: Iterator[tuple[int, SolRpcTxIxInfo]] | None
    _inner_ix_list_iter: Iterator[SolRpcTxInnerIxList] | None
    _inner_ix_list: SolRpcTxInnerIxList | None
    _inner_ix_iter: Iterator[SolRpcTxIxInfo] | None

    _BIG_INDEX: ClassVar[int] = 2**64

    def _next_ix(self) -> SolRpcTxIxInfo | None:
        ix_idx, ix = next(self._ix_iter, (self._BIG_INDEX, None))
        if ix is None:
            return None

        while self._inner_ix_list_idx < ix_idx:
            self._inner_ix_list = next(self._inner_ix_list_iter, None)
        self._inner_ix_iter = iter(self._inner_ix_list.instructions) if self._inner_ix_list_idx == ix_idx else None

        return ix

    def _next_inner_ix(self) -> SolRpcTxIxInfo | None:
        return next(self._inner_ix_iter, None) if self._inner_ix_iter is not None else None

    @property
    def _inner_ix_list_idx(self) -> int:
        return self._inner_ix_list.index if self._inner_ix_list is not None else self._BIG_INDEX


@dataclass
class _SolTxIxLogDraft:
    prog_id: SolPubKey
    level: int

    cu_limit: int
    used_cu_limit: int

    status: SolTxIxLogInfo.Status
    error: str | None

    log_list: list[str | SolTxIxLogInfo]
    inner_log_list: list[SolTxIxLogInfo]

    @classmethod
    def new_program_invoke(cls, prog_id: SolPubKey, level: int) -> Self:
        return cls(
            prog_id=prog_id,
            level=level,
            # default:
            status=SolTxIxLogInfo.Status.Unknown,
            cu_limit=0,
            used_cu_limit=0,
            error=None,
            log_list=list(),
            inner_log_list=list(),
        )

    @classmethod
    def default(cls) -> Self:
        return cls.new_program_invoke(prog_id=SolPubKey.default(), level=0)

    def to_clean_copy(self) -> SolTxIxLogInfo:
        return SolTxIxLogInfo(
            prog_id=self.prog_id,
            level=self.level,
            cu_limit=self.cu_limit,
            used_cu_limit=self.used_cu_limit,
            status=self.status,
            error=self.error,
            log_list=tuple(self.log_list),
            inner_log_list=tuple(self.inner_log_list),
        )

    def to_clean_tree(self) -> SolTxLogTreeInfo:
        return SolTxLogTreeInfo(log_list=tuple(self.log_list))


class _SolInvokeLogDecoder:
    _re: Final[re.Pattern] = re.compile(r"^Program (\w+) invoke \[(\d+)]$")

    @classmethod
    def decode(cls, raw: str) -> _SolTxIxLogDraft | None:
        match = cls._re.match(raw)
        if match is None:
            return None

        return _SolTxIxLogDraft.new_program_invoke(prog_id=SolPubKey.from_string(match[1]), level=int(match[2]))


class _SolSuccessLogDecoder:
    _re: Final[re.Pattern] = re.compile(r"^Program (\w+) success$")

    @classmethod
    def decode(cls, log: _SolTxIxLogDraft, raw: str) -> bool:
        match = cls._re.match(raw)
        if match is None:
            return False
        prog_id = SolPubKey.from_string(match[1])
        assert log.prog_id == prog_id

        log.status = log.status.Success
        return True


class _SolFailedLogDecoder:
    _re: Final[re.Pattern] = re.compile(r"^Program (\w+) failed: (.+)$")

    @classmethod
    def decode(cls, log: _SolTxIxLogDraft, raw: str) -> bool:
        match = cls._re.match(raw)
        if match is None:
            return False

        prog_id = SolPubKey.from_string(match[1])
        error = match[2]
        assert log.prog_id == prog_id

        log.status = SolTxIxLogInfo.Status.Failed
        log.error = error
        return True


class _SolCuLogDecoder:
    _re: Final[re.Pattern] = re.compile(r"^Program (\w+) consumed (\d+) of (\d+) compute units$")

    @classmethod
    def decode(cls, log: _SolTxIxLogDraft, raw: str) -> bool:
        if (log.cu_limit, log.used_cu_limit) != (0, 0):
            return False

        match = cls._re.match(raw)
        if match is None:
            return False

        log.cu_limit = int(match[3])
        log.used_cu_limit = int(match[2])
        return True

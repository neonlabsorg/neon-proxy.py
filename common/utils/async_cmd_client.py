from __future__ import annotations

import asyncio
import logging
from asyncio import StreamReader as AsyncStreamReader
from dataclasses import dataclass
from enum import IntEnum
from signal import Signals

from .cached import cached_property
from .json_logger import log_msg

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Process:
    program: str
    arg_list: list[str]

    return_code: int = 0
    stdout: str = None
    stderr: str = None

    def check_return_code(self) -> None:
        if self.return_code:
            raise ProcessError(self)

    @cached_property
    def cmd_line(self) -> str:
        return " ".join([self.program] + self.arg_list)


class ProcessError(Exception):
    def __init__(self, process: Process, error: str = None):
        super().__init__(process, error)
        self._process = process
        self._error = error

    @property
    def process(self) -> Process:
        return self._process

    def __str__(self):
        p = self._process
        if self._error:
            return f"Command '{p.cmd_line}' failed with the error '{self._error}'"

        if p.return_code and p.return_code < 0:
            try:
                reason = f"died with {Signals(-p.return_code)!r}"
            except ValueError:
                reason = f"died with unknown signal {-p.return_code}"
        else:
            reason = f"returned non-zero exit status {p.return_code}"
        return f"Command '{p.cmd_line}' {reason}"


class AsyncStreamType(IntEnum):
    StdOut = 1
    StdErr = 2


class AsyncCmdClient:
    def __init__(self, prog: str, debug_cmd_line: bool = False):
        self._prog = prog
        self._debug_cmd_line = debug_cmd_line
        self._msg_filter = None

    async def _run_cmd_client(self, arg_list: list[str]) -> Process:
        process = Process(self._prog, arg_list)
        if self._debug_cmd_line:
            _LOG.debug("running command: %s", process.cmd_line, extra=self._msg_filter)

        try:
            async_process = await asyncio.create_subprocess_exec(
                process.program,
                *process.arg_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.gather(
                self._read_stream(AsyncStreamType.StdOut, async_process.stdout),
                self._read_stream(AsyncStreamType.StdErr, async_process.stderr),
            )
            process = Process(
                program=process.program,
                arg_list=process.arg_list,
                return_code=async_process.returncode,
                stdout=stdout,
                stderr=stderr,
            )

            if not process.stdout:
                process.check_return_code()

        except ProcessError as exc:
            _LOG.error(log_msg("error on running command line: {Error}", Error=str(exc)), extra=self._msg_filter)
            raise
        except BaseException as exc:
            error = ProcessError(process, str(exc))
            _LOG.error("unexpected error on running command line", exc_info=exc, extra=self._msg_filter)
            raise error
        return process

    async def _read_stream(self, stream_type: AsyncStreamType, stream: AsyncStreamReader) -> str:
        if not self._debug_cmd_line:
            return await self._read_full_stream(stream_type, stream)
        return await self._read_stream_by_line(stream_type, stream)

    @staticmethod
    async def _read_full_stream(_: AsyncStreamType, stream: AsyncStreamReader) -> str:
        result: bytes = await stream.read()
        return str(result, "utf-8")

    async def _read_stream_by_line(self, _: AsyncStreamType, stream: AsyncStreamReader) -> str:
        result: str = ""
        while raw_line := await stream.readline():
            line = str(raw_line, "utf-8")
            result += line
            _LOG.debug("%s", line.rstrip(), extra=self._msg_filter)

        return result

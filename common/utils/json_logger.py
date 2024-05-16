from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import logging.config
import os
import pathlib
import traceback
from datetime import datetime
from logging import LogRecord, Filter


class Logger:
    """Common logging utilities and setup."""

    @staticmethod
    def setup() -> None:
        logging.basicConfig(
            level="INFO",
            format="%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(filename)s:%(lineno)d - %(message)s",
        )

        log_cfg_path = pathlib.Path("log_cfg.json")
        if log_cfg_path.exists() and log_cfg_path.is_file():
            with open(log_cfg_path, "r") as log_cfg_file:
                data = json.load(log_cfg_file)
                logging.config.dictConfig(data)


def log_msg(message: str, **kwargs) -> dict:
    return dict(message=message, **kwargs)


def _get_root_path_len() -> int:
    """Extract len of root for the current file.
    Logic is based on the path: $l2_pathname/ common/logger/logger.py
    """
    l0_pathname, _ = os.path.split(__file__)
    l1_pathname, _ = os.path.split(l0_pathname)
    l2_pathname, _ = os.path.split(l1_pathname)
    return len(l2_pathname) + 1


_SKIP_ROOTPATH_LEN = _get_root_path_len()
_BASE_ROOTPATH = __file__[:_SKIP_ROOTPATH_LEN]
_CLEF_LOG_FORMAT = os.environ.get("LOG_CLEF_FORMAT", "NO").upper() in ("YES", "ON", "TRUE", "1")


class JSONFormatter(logging.Formatter):
    def format(self, record: LogRecord) -> str:
        if _CLEF_LOG_FORMAT:
            return self._clef_format(record)
        return self._simple_format(record)

    def _clef_format(self, record: LogRecord) -> str:
        msg_dict = dict()
        if record.levelname != "INFO":
            msg_dict["@l"] = record.levelname

        pathname = record.pathname
        if pathname.startswith(_BASE_ROOTPATH):
            pathname = pathname[_SKIP_ROOTPATH_LEN:]

        msg_dict["@t"] = datetime.fromtimestamp(record.created).isoformat()
        msg_dict["@p"] = pathname + ":" + str(record.lineno)
        # msg_dict["process"] = record.process,

        msg_filter = record.msg_filter if hasattr(record, "msg_filter") else None
        if isinstance(record.msg, dict):
            if msg_filter:
                msg = {k: msg_filter(v) for k, v in record.msg.items()}
            else:
                msg = record.msg

            msg_dict["@mt"] = msg["message"]
            msg.pop("message")
            for k, v in msg.items():
                if hasattr(v, "to_string"):
                    msg_dict[k] = v.to_string()
                else:
                    msg_dict[k] = v
        else:
            msg = record.getMessage()
            if msg_filter:
                msg = msg_filter(msg)
            msg_dict["@m"] = msg

        if ctx := getattr(record, "context", None):
            msg_dict["@i"] = ctx

        if record.exc_info:
            exc_type, exc_msg, exc_tb, exc_text = self._get_exc_info(record, msg_filter)
            exc_info = {
                "Type": exc_type,
                "Error": exc_msg,
                "Traceback": exc_tb,
            }
            if exc_text:
                exc_info["Text"] = exc_text
            msg_dict["@x"] = exc_info
        return json.dumps(msg_dict)

    def _simple_format(self, record: LogRecord) -> str:
        pathname = record.pathname
        if pathname.startswith(_BASE_ROOTPATH):
            pathname = pathname[_SKIP_ROOTPATH_LEN:]

        msg_dict = {
            "level": record.levelname,
            "date": datetime.fromtimestamp(record.created).isoformat(),
            # "process": record.process,
            "module": pathname + ":" + str(record.lineno),
        }

        msg_filter = record.msg_filter if hasattr(record, "msg_filter") else None
        if isinstance(record.msg, dict):
            if msg_filter:
                msg = {k: msg_filter(v) for k, v in record.msg.items()}
            else:
                msg = record.msg

            base_msg = msg.pop("message", "")
            msg_dict["message"] = base_msg.format(**msg)

        else:
            msg = record.getMessage()
            if msg_filter:
                msg = msg_filter(msg)
            msg_dict["message"] = msg

        if ctx := getattr(record, "context", None):
            msg_dict.update(ctx)

        if record.exc_info:
            exc_type, exc_msg, exc_tb, exc_text = self._get_exc_info(record, msg_filter)
            exc_info = {
                "type": exc_type,
                "error": exc_msg,
                "traceback": exc_tb,
            }
            if exc_text:
                exc_info["text"] = exc_text
            msg_dict["exc_info"] = exc_info

        return json.dumps(msg_dict)

    @staticmethod
    def _get_exc_info(record: LogRecord, msg_filter) -> tuple[str, str, tuple[str, ...], str | None]:
        exc_msg = str(record.exc_info[1])
        if msg_filter:
            exc_msg = msg_filter(exc_msg)
        exc_type = str(record.exc_info[0])
        exc_tb = map(
            lambda line: line.strip().replace('"', "'").replace("\n", "; ").replace(_BASE_ROOTPATH, ""),
            traceback.format_tb(record.exc_info[2]),
        )
        if record.exc_text:
            exc_text = record.exc_text
            if msg_filter:
                exc_text = msg_filter(exc_text)
        else:
            exc_text = None
        return exc_type, exc_msg, tuple(exc_tb), exc_text


_LOG_CTX = contextvars.ContextVar("log_context", default=dict())


class ContextFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        record.context = _LOG_CTX.get()
        return True


@contextlib.contextmanager
def logging_context(**kwargs):
    old_log_ctx = _LOG_CTX.get()

    new_log_ctx = dict(**old_log_ctx)
    new_log_ctx.update(kwargs)
    _LOG_CTX.set(new_log_ctx)

    try:
        yield
    finally:
        _LOG_CTX.set(old_log_ctx)

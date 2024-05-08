from __future__ import annotations

from typing import Callable, Sequence

from .config import Config


def LogMsgFilter(cfg: Config) -> dict:  # noqa
    if cfg.hide_sensitive_info:
        return dict(msg_filter=_hide_sensitive_info(cfg))
    return dict()


def hide_sensitive_info(msg_filter: dict, value: str | Sequence[str]) -> str | list[str]:
    if "msg_filter" in msg_filter:
        return msg_filter["msg_filter"](value)
    return value


def _hide_sensitive_info(cfg: Config) -> Callable:
    def _empty_wrapper(value):
        return value

    def _wrapper(value: str | list[str]) -> str | list[str]:
        if isinstance(value, str):
            return _hide_sensitive_in_str(value, cfg)
        elif isinstance(value, list):
            return _hide_sensitive_in_list(value, cfg)
        return value

    if not cfg.hide_sensitive_info:
        return _empty_wrapper

    return _wrapper


def _hide_sensitive_in_str(value: str, cfg: Config) -> str:
    for item in cfg.sensitive_info_list:
        value = value.replace(item, "*****")
    return value


def _hide_sensitive_in_list(value_list: Sequence[str], cfg: Config) -> list[str]:
    return [_hide_sensitive_in_str(value, cfg) if isinstance(value, str) else value for value in value_list]

from __future__ import annotations

import logging

_LOG = logging.getLogger(__name__)


class MetricsLogger:
    def __init__(self, skip_log_cnt: int):
        self._skip_log_cnt = skip_log_cnt
        self._counter: int = 0

    def _reset(self):
        self._counter = 0

    @property
    def is_print_time(self) -> bool:
        self._counter += 1
        return (self._counter % self._skip_log_cnt) == 0

    def print(self, latest_value_dict: dict[str, int]):
        _LOG.debug("%s", latest_value_dict)
        self._reset()

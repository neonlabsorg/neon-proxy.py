import time
from collections import deque

from .api import HealthErrorData, HealthErrorModel
from ..config.config import Config


class HealthErrorRegistry:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._error_list_dict: dict[str, deque[HealthErrorData]] = dict()

    def get_health_error_list(self) -> dict[str, list[HealthErrorModel]]:
        now_sec = int(time.time())
        self._clear_error_list(now_sec)

        # fmt: off
        return {
            key: [HealthErrorModel.from_raw(e, now_sec) for e in error_list]
            for key, error_list in self._error_list_dict.items()
            if error_list
        }
        # fmt: on

    def add_error(self, name: str, message: str) -> None:
        if not (error_list := self._error_list_dict.get(name, None)):
            self._error_list_dict[name] = error_list = deque(maxlen=self._cfg.health_error_list_max_len)
        else:
            for error in error_list:
                if error.message == message:
                    return

        now_sec = int(time.time())
        error_list.appendleft(HealthErrorData(time_sec=now_sec, message=message))

    def clear_error(self, name: str) -> None:
        self._error_list_dict.pop(name, None)

    def _clear_error_list(self, now_sec: int) -> None:
        last_valid_sec = now_sec - self._cfg.health_error_timeout_sec
        for error_list in self._error_list_dict.values():
            while error_list and (error_list[-1].time_sec < last_valid_sec):
                error_list.pop()

import time
from collections import deque

from .api import HealthErrorData, HealthErrorModel, HealthErrorCode
from ..config.config import Config


class HealthErrorRegistry:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._error_list_dict: dict[str, deque[HealthErrorData]] = dict()

    def get_health_error_list(self) -> dict[str, list[HealthErrorModel]]:
        now_sec = int(time.time())

        # fmt: off
        return {
            key: [HealthErrorModel.from_raw(e, now_sec) for e in error_list]
            for key, error_list in self._error_list_dict.items()
            if error_list
        }
        # fmt: on

    def add_error(self, name: str, code: HealthErrorCode, message: str, data: dict | None) -> None:
        now_sec = int(time.time())

        if not (error_list := self._error_list_dict.get(name, None)):
            self._error_list_dict[name] = error_list = deque(maxlen=self._cfg.health_error_list_max_len)
        else:
            for error in error_list:
                if (
                    error.code == code and
                    error.message == message and
                    error.calc_age(now_sec) < self._cfg.health_error_max_age
                ):
                    return

        error_list.appendleft(HealthErrorData(code=code, time_sec=now_sec, message=message, data=data))

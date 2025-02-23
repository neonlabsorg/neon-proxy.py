import time
from collections import deque

from .api import HealthErrorData, HealthErrorModel, HealthErrorCode, HealthStatusModel, HealthStatus
from ..config.config import Config


class HealthErrorRegistry:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._error_age_sec = cfg.health_error_max_age * 3
        self._warn_age_sec = cfg.health_error_max_age * 10
        self._service_set: set[str] = set()
        self._good_time_dict: dict[str, int] = dict()
        self._error_list_dict: dict[str, deque[HealthErrorData]] = dict()

    def get_health_status(self) -> dict[str, HealthStatusModel]:
        monotonic_sec = int(time.monotonic())

        return {
            service: self._calc_service_status(service, monotonic_sec)
            for service in self._service_set
        }

    def add_error(self, name: str, code: HealthErrorCode, message: str, data: dict | None) -> None:
        monotonic_sec = int(time.monotonic())

        if not (error_list := self._error_list_dict.get(name, None)):
            self._error_list_dict[name] = error_list = deque(maxlen=self._cfg.health_error_list_max_len)
            self._service_set.add(name)
        else:
            for error in error_list:
                if error.calc_age(monotonic_sec) > self._cfg.health_error_max_age:
                    break
                elif (error.code == code) and (error.message == message):
                    return

        now_sec = int(time.time())
        error_list.appendleft(
            HealthErrorData(
                code=code,
                time_sec=now_sec,
                monotonic_sec=monotonic_sec,
                message=message,
                data=data,
            )
        )

    def add_good_time(self, name: str) -> None:
        self._service_set.add(name)
        self._good_time_dict[name] = int(time.monotonic())

    def _calc_service_status(self, name: str, monotonic_sec: int) -> HealthStatusModel:
        total_age, is_good_status = 0, True
        error_list: list[HealthErrorModel] = list()

        if base_error_list := self._error_list_dict.get(name, None):
            last_error = base_error_list[0]
            good_sec = self._good_time_dict.get(name, 0)

            if (total_age := last_error.calc_age(monotonic_sec)) > self._warn_age_sec:
                pass
            elif last_error.calc_age(good_sec) > self._error_age_sec:
                pass
            else:
                is_good_status = False

            error_list = [HealthErrorModel.from_raw(e, monotonic_sec) for e in base_error_list]

        return HealthStatusModel(
            status=HealthStatus.Good if is_good_status else HealthStatus.Error,
            error_age=total_age,
            error_list=error_list,
        )

import dataclasses
import itertools
import time
import uuid
from collections import deque
from typing import Sequence

from .api import HealthErrorModel, HealthErrorCode, HealthServiceStatusModel, HealthStatus, HealthShortStatusModel
from ..config.config import Config
from ..utils.cached import cached_property


@dataclasses.dataclass(frozen=True)
class _HealthErrorData:
    id: int
    code: HealthErrorCode
    mono_sec: int
    time_sec: int
    message: str
    data: dict | None

    def calc_age(self, mono_sec: int) -> int:
        return mono_sec - self.mono_sec

    def to_clean_copy(self, now_sec: int) -> HealthErrorModel:
        return self._clean_copy.model_copy(update=dict(age=self.calc_age(now_sec)))

    @cached_property
    def _clean_copy(self) -> HealthErrorModel:
        return HealthErrorModel(
            id=self.id,
            time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.time_sec)),
            code=self.code,
            timestamp=self.time_sec,
            message=self.message,
            data=self.data,
            age=0,
        )


class HealthErrorRegistry:
    def __init__(self, name: str, cfg: Config) -> None:
        self._name = name
        self._cfg = cfg
        self._err_age_sec = cfg.health_error_max_age * 3
        self._warn_age_sec = cfg.health_error_max_age * 10

        self._id = itertools.count(1)
        self._last_err: _HealthErrorData | None = None

        self._service_set: set[str] = set()
        self._good_time_dict: dict[str, int] = dict()
        self._err_list_dict: dict[str, deque[_HealthErrorData]] = dict()

    @property
    def status(self) -> HealthShortStatusModel:
        mono_sec = self._mono_sec()
        last_err_id = self._last_err.id if self._last_err else 0

        for service_name, err_list in self._err_list_dict.items():
            if active_err := self._is_active_error(service_name, mono_sec, err_list):
                return self._status.model_copy(
                    update=dict(
                        status=HealthStatus.Error,
                        errorLastId=last_err_id,
                        errorService=service_name,
                        errorMessage=active_err.message,
                    ),
                )

        return self._status.model_copy(update=dict(errorLastId=last_err_id))

    @property
    def service_list(self) -> dict[str, HealthServiceStatusModel]:
        mono_sec = self._mono_sec()
        return {service: self._build_service_status(service, mono_sec) for service in self._service_set}

    def add_error(self, name: str, code: HealthErrorCode, message: str, data: dict | None) -> None:
        mono_sec = self._mono_sec()

        if not (err_list := self._err_list_dict.get(name, None)):
            err_list = deque(maxlen=self._cfg.health_error_list_max_len)
            self._err_list_dict[name] = err_list
            self._service_set.add(name)
        else:
            for err in err_list:
                if err.code != code:
                    continue
                elif err.calc_age(mono_sec) > self._cfg.health_error_max_age:
                    break
                elif err.message == message:
                    return

        self._last_err = _HealthErrorData(
            id=next(self._id),
            code=code,
            time_sec=int(time.time()),
            mono_sec=mono_sec,
            message=message,
            data=data,
        )
        err_list.appendleft(self._last_err)

    def add_good_time(self, name: str) -> None:
        self._service_set.add(name)
        self._good_time_dict[name] = self._mono_sec()

    @staticmethod
    def _mono_sec() -> int:
        return int(time.monotonic())

    def _build_service_status(self, service_name: str, mono_sec: int) -> HealthServiceStatusModel:
        active_err: _HealthErrorData | None = None
        err_list: list[HealthErrorModel] = list()

        if base_err_list := self._err_list_dict.get(service_name, None):
            active_err = self._is_active_error(service_name, mono_sec, base_err_list)
            err_list = [e.to_clean_copy(mono_sec) for e in base_err_list]

        return HealthServiceStatusModel(
            status=HealthStatus.Good if not active_err else HealthStatus.Error,
            errorAge=active_err.calc_age(mono_sec) if active_err else 0,
            errors=err_list,
        )

    def _is_active_error(
        self, service_name: str, mono_sec: int, err_list: _HealthErrorData | Sequence[_HealthErrorData] | None
    ) -> _HealthErrorData | None:
        if not err_list:
            return err_list
        elif not isinstance(err_list, _HealthErrorData):
            err = err_list[0]
        else:
            err = err_list

        if err.calc_age(mono_sec) > self._warn_age_sec:
            return None
        elif err.calc_age(self._good_time_dict.get(service_name, 0)) > self._err_age_sec:
            return None

        return err

    @cached_property
    def _status(self) -> HealthShortStatusModel:
        return HealthShortStatusModel(
            name=self._name,
            startTime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            uuid=str(uuid.uuid4()),
            status=HealthStatus.Good,
            errorLastId=0,
            errorService="",
            errorMessage="",
        )

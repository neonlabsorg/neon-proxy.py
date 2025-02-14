import dataclasses
import time

from pydantic import Field
from typing_extensions import Self

from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel


class RpcCallData(BaseModel):
    service: str
    method: str
    time_nsec: int
    is_error: bool = False
    error_message: str | None = None
    is_modification: bool = False


@dataclasses.dataclass(frozen=True)
class HealthErrorData:
    time_sec: int
    message: str

    @cached_property
    def time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.time_sec))

    def calc_age(self, now_sec: int) -> int:
        return now_sec - self.time_sec

class HealthErrorModel(BaseModel):
    time: str
    age: int
    message: str

    @classmethod
    def from_raw(cls, raw: HealthErrorData, now_sec: int) -> Self:
        return cls(time=raw.time, age=raw.calc_age(now_sec), message=raw.message)


class HealthErrorListFormatter(BaseModel):
    error_list: dict[str, list[HealthErrorModel]] = Field(serialization_alias="errors")


class MetricStatData(BaseModel):
    data: str


class HealthCheckData(BaseModel):
    data: str

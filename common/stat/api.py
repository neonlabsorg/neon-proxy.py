import dataclasses
import enum
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


class HealthErrorCode(enum.IntEnum):
    RPCError = 1
    RPCBigTimeError = 2
    CorruptedBlockError = 3
    LagBlockError = 4
    DisabledHolderError = 5
    UsedHolderError = 6
    FullMempoolError = 7
    StuckTxError = 8


@dataclasses.dataclass(frozen=True)
class HealthErrorData:
    code: HealthErrorCode
    time_sec: int
    message: str
    data: dict | None

    @cached_property
    def time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.time_sec))

    def calc_age(self, now_sec: int) -> int:
        return now_sec - self.time_sec

class HealthErrorModel(BaseModel):
    time: str
    timestamp: int
    age: int
    code: int
    message: str
    data: dict | None

    @classmethod
    def from_raw(cls, raw: HealthErrorData, now_sec: int) -> Self:
        return cls(
            time=raw.time,
            code=int(raw.code),
            timestamp=raw.time_sec,
            age=raw.calc_age(now_sec),
            message=raw.message,
            data=raw.data,
        )


class HealthErrorListFormatter(BaseModel):
    error_list: dict[str, list[HealthErrorModel]] = Field(serialization_alias="errors")


class MetricStatData(BaseModel):
    data: str


class HealthCheckData(BaseModel):
    data: str


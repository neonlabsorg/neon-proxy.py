import dataclasses
import enum
import time

import strenum
from pydantic import Field, PlainSerializer
from typing_extensions import Self, Annotated

from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel


class RpcCallData(BaseModel):
    service: str
    method: str
    time_nsec: int
    is_error: bool = False
    error_message: str | None = None
    is_modification: bool = False


class HealthServiceName(strenum.StrEnum):
    BlockStorage = "BlockStorage"
    Holder = "Holders"
    Mempool = "Mempool"


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
    monotonic_sec: int
    time_sec: int
    message: str
    data: dict | None

    @cached_property
    def time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.time_sec))

    def calc_age(self, monotonic_sec: int) -> int:
        return monotonic_sec - self.monotonic_sec

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


class HealthStatus(strenum.StrEnum):
    Good = "ok"
    Error = "error"


HealthStatusField = Annotated[HealthStatus, PlainSerializer(lambda x: x.value)]


class HealthStatusModel(BaseModel):
    status: HealthStatusField
    error_age: int = Field(serialization_alias="errorAge")
    error_list: list[HealthErrorModel] = Field(default_factory=list, serialization_alias="errors")


class HealthErrorListFormatter(BaseModel):
    service_list: dict[str, HealthStatusModel] = Field(serialization_alias="services")


class MetricStatData(BaseModel):
    data: str


class HealthCheckData(BaseModel):
    data: str


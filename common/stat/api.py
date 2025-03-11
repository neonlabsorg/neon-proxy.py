import enum

import strenum
from pydantic import Field, PlainSerializer, PlainValidator
from typing_extensions import Self, Annotated

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


class HealthErrorModel(BaseModel):
    id: int
    time: str
    timestamp: int
    age: int
    code: int
    message: str
    data: dict | None


class HealthStatus(strenum.StrEnum):
    Good = "ok"
    Error = "error"

    @classmethod
    def from_raw(cls, value: str) -> Self:
        return cls(value)


HealthStatusField = Annotated[HealthStatus, PlainSerializer(lambda x: x.value), PlainValidator(HealthStatus.from_raw)]


class HealthShortStatusModel(BaseModel):
    name: str
    startTime: str
    uuid: str
    status: HealthStatusField
    errorLastId: int
    errorService: str
    errorMessage: str


class HealthServiceStatusModel(BaseModel):
    status: HealthStatusField
    errorAge: int
    errors: list[HealthErrorModel] = Field(default_factory=list)


class HealthFullStatusModel(BaseModel):
    name: str
    startTime: str
    uuid: str
    status: HealthStatusField
    errorLastId: int
    services: dict[str, HealthServiceStatusModel]

    @classmethod
    def from_raw(cls, status: HealthShortStatusModel, service_list: dict[str, HealthServiceStatusModel]) -> Self:
        return cls(
            name=status.name,
            startTime=status.startTime,
            uuid=status.uuid,
            errorLastId=status.errorLastId,
            status=status.status,
            services=service_list,
        )


class MetricStatData(BaseModel):
    data: str

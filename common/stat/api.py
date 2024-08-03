from ..utils.pydantic import BaseModel


class RpcCallData(BaseModel):
    service: str
    method: str
    is_error: bool
    time_nsec: int


class MetricStatData(BaseModel):
    data: str

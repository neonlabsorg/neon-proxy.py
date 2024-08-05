from ..utils.pydantic import BaseModel


class RpcCallData(BaseModel):
    service: str
    method: str
    time_nsec: int
    method_name: str = "method"
    is_error: bool = False
    is_modification: bool = False


class MetricStatData(BaseModel):
    data: str

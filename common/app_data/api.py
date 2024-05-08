from __future__ import annotations

from ..http.utils import HttpRequestIdField
from ..utils.pydantic import BaseModel


class AppErrorModel(BaseModel):
    code: int = -1
    message: str = None
    data: dict | None = None


class AppRequest(BaseModel):
    id: HttpRequestIdField
    data: dict | None


class AppResp(BaseModel):
    id: HttpRequestIdField

    error: AppErrorModel | None = None
    result: dict | None = None

    def is_error(self) -> bool:
        return self.error is not None

    def is_result(self) -> bool:
        return self.result is not None

    def model_post_init(self, _context) -> None:
        if self.is_result() and (self.is_error() == self.is_result()):
            raise ValueError("Response cannot have both 'error' and 'result' fields")

    def model_dump_json(self, *args, **kwargs) -> str:
        kwargs.pop("exclude", None)
        exclude_set = {"result"} if self.is_error() else {"error"}
        return super().model_dump_json(*args, exclude=exclude_set, **kwargs)

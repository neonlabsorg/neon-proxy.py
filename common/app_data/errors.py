from __future__ import annotations

from typing import Sequence

from ..http.errors import BaseHttpError, PydanticValidationError


class BaseAppDataError(BaseHttpError):
    def __init__(
        self,
        message: str,
        code: int = -1,
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        super().__init__(message, error_list)
        self._code = code

    @property
    def code(self) -> int:
        return self._code


class BadRespError(BaseAppDataError):
    CODE = 10000

    def __init__(self, error: BaseException | None = None, error_list: str | Sequence[str] = tuple()):
        error_list = self._create_error_list(error, error_list)
        super().__init__("Bad response from the server", code=self.CODE, error_list=error_list)


class AppRequestValidationError(BaseAppDataError):
    CODE = 10001

    def __init__(self, src: PydanticValidationError) -> None:
        error_list = self._format_pydantic_error_list(src)
        super().__init__("Request validation error", self.CODE, error_list)

from ..http.errors import PydanticValidationError
from ..simple_app_data.errors import BaseAppDataError as _BaseAppError, BadRespError as _BadRespError


BadRespError = _BadRespError
BaseAppDataError = _BaseAppError


class AppRequestValidationError(_BaseAppError):
    CODE = 10001

    def __init__(self, src: PydanticValidationError) -> None:
        error_list = self._format_pydantic_error_list(src)
        super().__init__("Request validation error", self.CODE, error_list)

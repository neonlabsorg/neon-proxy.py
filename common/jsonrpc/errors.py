from __future__ import annotations

from typing import Sequence

from ..http.errors import BaseHttpError, PydanticValidationError


class BaseJsonRpcError(BaseHttpError):
    CODE = -32000

    def __init__(
        self,
        message: str,
        *,
        error_list: str | Sequence[str] = tuple(),
        code: int = CODE,
        data: str | None = None,
    ) -> None:
        super().__init__(message, error_list)
        self._code = code
        self._data = data

    @property
    def code(self) -> int:
        return self._code

    @property
    def data(self) -> str | None:
        return self._data


class ParseRequestError(BaseJsonRpcError):
    """Invalid JSON was received by the server"""

    CODE = -32700

    def __init__(
        self,
        src: BaseException | None = None,
        *,
        code: int = CODE,
        message: str = "Invalid JSON was received by the server",
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        error_list = self._create_error_list(src, error_list)
        super().__init__(code=code, message=message, error_list=error_list)


class ParseRespError(BaseJsonRpcError):
    """Invalid JSON was returned by the server"""

    CODE = -32700

    def __init__(
        self,
        src: BaseException | None = None,
        *,
        code: int = CODE,
        message: str = "Invalid JSON was returned by the server",
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        error_list = self._create_error_list(src, error_list)
        super().__init__(code=code, message=message, error_list=error_list)


class MethodNotFoundError(BaseJsonRpcError):
    """The method does not exist / is not available"""

    CODE = -32601

    def __init__(
        self,
        method_name: str = None,
        *,
        code: int = CODE,
        message: str = None,
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        if method_name is not None:
            assert message is None
            message = f"the method {method_name} does not exist/is not available"
        super().__init__(code=code, message=message, error_list=error_list)


class InvalidParamError(BaseJsonRpcError):
    """Invalid method parameter(s)"""

    CODE = -32602

    def __init__(
        self,
        src: BaseException | None = None,
        *,
        code: int = CODE,
        message: str = None,
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        error_list = self._create_error_list(src, error_list)

        if message is None:
            message = "invalid parameters"
            if isinstance(src, PydanticValidationError) and (src.error_count() == 1):
                error_loc = list(src.errors())[0]["loc"]
                input_name = ".".join(str(v) for v in error_loc)
                message = "invalid parameter " + input_name

        super().__init__(code=code, message=message, error_list=error_list)


class InternalJsonRpcError(BaseJsonRpcError):
    """Internal JSON-RPC error"""

    CODE = -32603

    def __init__(
        self,
        src: BaseException | None = None,
        *,
        code: int = CODE,
        message: str = "internal error",
        error_list: str | Sequence[str] = tuple(),
    ) -> None:
        error_list = self._create_error_list(src, error_list)
        super().__init__(code=code, message=message, error_list=error_list)


JsonRpcErrorDict: dict[int, type[BaseJsonRpcError]] = {
    BaseJsonRpcError.CODE: BaseJsonRpcError,
    ParseRequestError.CODE: ParseRequestError,
    MethodNotFoundError.CODE: MethodNotFoundError,
    InvalidParamError.CODE: InvalidParamError,
    InternalJsonRpcError.CODE: InternalJsonRpcError,
}

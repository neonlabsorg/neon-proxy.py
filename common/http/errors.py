from __future__ import annotations

from typing import Sequence

from pydantic import ValidationError as PydanticValidationError


class BaseHttpError(Exception):
    def __init__(self, message: str, error_list: str | Sequence[str]):
        self._msg = message
        if isinstance(error_list, str):
            self._error_list = tuple([error_list])
        else:
            self._error_list = tuple(error_list)

    @property
    def message(self) -> str:
        return self._msg

    @property
    def error_list(self) -> Sequence[str]:
        return self._error_list

    def __str__(self) -> str:
        return self._msg + ". " + ". ".join(self._error_list)

    @classmethod
    def _create_error_list(
        cls,
        src: BaseException | None,
        src_error_list: str | Sequence[str],
    ) -> list[str]:
        res_error_list: list[str] = list()
        if isinstance(src, PydanticValidationError):
            res_error_list = cls._format_pydantic_error_list(src)
        elif src:
            res_error_list = [str(src)]

        if isinstance(src_error_list, str):
            res_error_list.append(src_error_list)
        elif src_error_list:
            res_error_list.extend(src_error_list)

        return res_error_list

    @staticmethod
    def _format_pydantic_error_list(src: PydanticValidationError) -> list[str]:
        error_list: list[str] = list()
        if not src:
            return error_list

        for error in src.errors():
            input_name = ".".join(str(v) for v in error["loc"])
            msg = error["msg"]

            # input_value = error["input"]
            # if isinstance(input_value, str):
            #     input_value = "'" + input_value + "'"

            # error_str = f"The parameter {input_name}={input_value}: {msg}."
            error_str = f"The parameter '{input_name}': {msg}."
            error_list.append(error_str)

        return error_list


class Http50xError(BaseHttpError):
    pass


class HttpRouteError(Exception):
    pass

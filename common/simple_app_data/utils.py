from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Callable

from typing_extensions import Self

from ..http.utils import HttpMethod, http_validate_method_name
from ..utils.pydantic import BaseModel


@dataclass(frozen=True)
class SimpleAppDataMethod(HttpMethod):
    RequestType: type[BaseModel] | None
    RespType: type[BaseModel]

    @classmethod
    def from_handler(
        cls,
        handler: Callable,
        name: str = None,
        allow_request_ctx: bool = False,
    ) -> Self:
        method = HttpMethod.from_handler(handler, allow_request_ctx)

        assert issubclass(method.ReturnType, BaseModel), "AppDataMethod must return an BaseModel instance"
        assert len(method.param_name_list) in (0, 1), "AppDataMethod must have only 1 argument"

        if len(method.param_name_list) == 1:
            req_param_name = method.param_name_list[0]
            _RequestType = method.type_hint_dict.get(req_param_name)
            assert issubclass(_RequestType, BaseModel), "AppDataMethod must accept an BaseModel instance"
        else:
            _RequestType = None

        kwargs = dataclasses.asdict(method)
        kwargs.pop("name")

        name = name or method.name
        http_validate_method_name(name)  # can raise assert exception

        return cls(
            **kwargs,
            name=name,
            RequestType=_RequestType,
            RespType=method.ReturnType,
        )

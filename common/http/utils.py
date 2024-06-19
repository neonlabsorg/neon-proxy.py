from __future__ import annotations

import hashlib
import inspect
import re
import time
import typing
from dataclasses import dataclass
from inspect import Signature
from types import NoneType
from typing import Any, Callable, Sequence, Union, Annotated, Final

import aiohttp.typedefs
from pydantic import PlainValidator
from robyn import Request as HttpRequest
from typing_extensions import Self

from ..utils.cached import cached_property

HttpURL = aiohttp.typedefs.URL
HttpStrOrURL = aiohttp.typedefs.StrOrURL
HttpRequestId = Union[str, int, None]

_METHOD_REGEX: Final[re.Pattern] = re.compile(r"^[a-zA-Z]+[a-zA-Z0-9_\-]+[a-zA-Z0-9]+$")
_X_FORWARDED_FOR = "X-Forwarded-For"
_EMPTY_OBJ = object()


@dataclass(frozen=True)
class HttpRequestCtx:
    path: str
    request: HttpRequest
    req_id: HttpRequestId
    start_time_nsec: int

    # protected:
    _prop_name_set: set[str]

    @classmethod
    def from_raw(
        cls,
        path: str,
        *,
        ctx: HttpRequestCtx | None = None,
        request: HttpRequest | object = _EMPTY_OBJ,
        req_id: HttpRequestId | object = _EMPTY_OBJ,
        start_time_nsec: int | None = None,
        sub_path: str | None = None,
    ) -> Self:
        if ctx:
            start_time_nsec = start_time_nsec or ctx.start_time_nsec or time.monotonic_ns()
            request = ctx.request if request is _EMPTY_OBJ else request
            req_id = ctx.req_id if req_id is _EMPTY_OBJ else req_id
            prop_set = ctx._prop_name_set
        else:
            start_time_nsec = start_time_nsec or time.monotonic_ns()
            req_id = None if req_id is _EMPTY_OBJ else req_id
            prop_set = set()

        if sub_path:
            path = "/" + sub_path if path == "/" else path + "/" + sub_path

        self = cls(path=path, request=request, req_id=req_id, start_time_nsec=start_time_nsec, _prop_name_set=prop_set)

        for prop_name in prop_set:
            self.set_property_value(prop_name, getattr(ctx, prop_name))

        return self

    @cached_property
    def ctx_id(self) -> str:
        if ctx_id := getattr(self, "_ctx_id", None):
            return ctx_id

        size = len(self.request.body)
        raw_value = f"{self.ip_addr}:{size}:{self.start_time_nsec}"
        ctx_id = hashlib.md5(bytes(raw_value, "utf-8")).hexdigest()[:8]
        self.set_property_value("_ctx_id", ctx_id)
        return ctx_id

    @cached_property
    def chain_id(self) -> int:
        chain_id = getattr(self, "_chain_id", None)
        assert chain_id is not None
        return chain_id

    @cached_property
    def body(self) -> str:
        value = self.request.body
        if isinstance(value, bytes):
            value = str(value, "utf-8")
        return value

    @cached_property
    def ip_addr(self) -> str:
        if self.request.headers.contains(_X_FORWARDED_FOR):
            ip_addr_list: str = self.request.headers.get(_X_FORWARDED_FOR)
            ip_addr = ip_addr_list.split(",")[0].strip()
        else:
            ip_addr = self.request.ip_addr

        self._prop_name_set.add("ip_addr")
        return ip_addr

    def set_req_id(self, value: HttpRequestIdField) -> Self:
        object.__setattr__(self, "req_id", value)
        return self

    @property
    def process_time_nsec(self) -> int:
        if self.start_time_nsec:
            return time.monotonic_ns() - self.start_time_nsec
        return 0

    @property
    def process_time_msec(self) -> float:
        return self.process_time_nsec / (10**6)

    def set_property_value(self, name: str, value) -> Self:
        object.__setattr__(self, name, value)
        self._prop_name_set.add(name)
        return self


@dataclass(frozen=True)
class HttpMethod:
    handler: Callable

    name: str
    module: str

    is_async_def: bool
    signature: Signature
    type_hint_dict: dict[str, Any]

    has_self: bool
    has_ctx: bool
    param_name_list: Sequence[str]
    ReturnType: type

    @classmethod
    def from_handler(cls, handler: Callable, *, allow_request_ctx: bool) -> Self:
        assert inspect.isfunction(handler), f"Handler {handler} is not a function"

        signature = inspect.signature(handler)
        type_hint_dict = typing.get_type_hints(handler)
        param_name_list = [v.name for v in signature.parameters.values()]

        # check predefined params
        has_self, param_name_list = _has_self(param_name_list)
        has_ctx, param_name_list = _has_ctx(param_name_list, type_hint_dict)
        assert not has_ctx or allow_request_ctx, "Handler doesn't support 'ctx' parameter"

        # Type of the return value
        _ReturnType = type_hint_dict.get("return", NoneType)

        return cls(
            handler=handler,
            name=handler.__name__,
            module=handler.__module__,  # noqa
            is_async_def=inspect.iscoroutinefunction(handler),
            signature=signature,
            type_hint_dict=type_hint_dict,
            has_self=has_self,
            has_ctx=has_ctx,
            param_name_list=param_name_list,
            ReturnType=_ReturnType,
        )


def _has_self(param_name_list: list[str]) -> tuple[bool, list[str]]:
    if param_name_list and (param_name_list[0] == "self"):
        return True, param_name_list[1:]
    return False, param_name_list


def _has_ctx(param_name_list: list[str], type_hint_dict: dict[str, Any]) -> tuple[bool, list[str]]:
    ctx_name: Final[str] = "ctx"
    if param_name_list and (param_name_list[0] == ctx_name):
        _HttpRequestType = type_hint_dict.get(ctx_name)
        assert issubclass(_HttpRequestType, HttpRequestCtx), f"{ctx_name} should have the type HttpRequestCtx"
        return True, param_name_list[1:]
    return False, param_name_list


def http_validate_method_name(name: str) -> None:
    assert isinstance(name, str)
    assert _METHOD_REGEX.fullmatch(name), f"Invalid method name {name}"


def _validate_request_id(value: HttpRequestId) -> HttpRequestId:
    if (value is None) or isinstance(value, int) or isinstance(value, str):
        return value
    raise ValueError("'id' must be a string or integer")


HttpRequestIdField = Annotated[HttpRequestId, PlainValidator(_validate_request_id)]

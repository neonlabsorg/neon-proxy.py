from __future__ import annotations

import collections
import dataclasses
import typing
from dataclasses import dataclass
from typing import Callable, Sequence

import pydantic
from pydantic import Field
from typing_extensions import Self

from .api import BaseJsonRpcModel, JsonRpcListMixin
from ..http.utils import HttpMethod, http_validate_method_name
from ..utils.pydantic import BaseModel, RootModel


@dataclass(frozen=True)
class JsonRpcMethod(HttpMethod):
    predefined_params: bool

    RequestList: type[JsonRpcListMixin] | None
    RequestValidator: type[BaseModel]
    ReturnValidator: type[BaseModel] | None

    @classmethod
    def from_handler(
        cls,
        handler: Callable,
        name: str = None,
        predefined_params: bool = False,
        is_batch: bool = False,
        allow_request_ctx: bool = False,
    ) -> Self:
        method = HttpMethod.from_handler(handler, allow_request_ctx=allow_request_ctx)

        req = (
            _parse_params_request(method, is_batch)
            if predefined_params
            else _create_request_validator(method, is_batch)
        )
        resp = _create_return_validator(method, is_batch)

        kwargs = dataclasses.asdict(method)
        kwargs.pop("name")
        kwargs.pop("param_name_list")
        kwargs.pop("ReturnType")

        name = name or method.name
        http_validate_method_name(name)

        return cls(
            **kwargs,
            name=name,
            param_name_list=req.param_name_list,
            predefined_params=req.predefined_params,
            RequestList=req.RequestList,
            RequestValidator=req.RequestValidator,
            ReturnType=resp.ReturnType,
            ReturnValidator=resp.ReturnValidator,
        )


@dataclass(frozen=True)
class _RequestInfo:
    predefined_params: bool
    param_name_list: Sequence[str]
    RequestList: type[JsonRpcListMixin] | None
    RequestValidator: type[BaseModel]


def _create_request_validator(method: HttpMethod, is_batch: bool) -> _RequestInfo:
    assert not is_batch, "Batch sender accepts only predefined Params"

    # Get parameters from the method signature
    param_list = [method.signature.parameters.get(n) for n in method.param_name_list]
    param_dict = {p.name: (p.annotation, Field(...) if p.default is p.empty else p.default) for p in param_list}

    # Create pydantic.BaseModel for input parameters validation
    _RequestValidator = pydantic.create_model(
        f"_JsonRpcRequest[{method.module}:{method.name}]",
        __module__=method.module,
        __base__=BaseModel,
        **param_dict,
    )

    return _RequestInfo(
        predefined_params=False,
        param_name_list=method.param_name_list,
        RequestList=None,
        RequestValidator=_RequestValidator,
    )


def _parse_params_request(method: HttpMethod, is_batch: bool) -> _RequestInfo:
    assert len(method.param_name_list) == 1, "Method with predefined Params accept only one parameter"
    param_name = method.param_name_list[0]

    if is_batch:
        assert param_name == "params_list", "The name of predefined Params in batch-mode must be 'params_list'"

        _RequestList = method.type_hint_dict.get(param_name)
        assert issubclass(_RequestList, RootModel), "'params_list' must be based on RootModel"
        assert issubclass(_RequestList, JsonRpcListMixin), "'params_list' must be based on JsonRpcListMixin"

        param_attr_dict = typing.get_type_hints(_RequestList)
        assert "root" in param_attr_dict, "'params_list' must have defined 'root'"
        _RootType = param_attr_dict.get("root")

        _ListType = typing.get_origin(_RootType)
        assert hasattr(_ListType, "__iter__"), "'params_list.root' must be iterable"

        _ArgListType = typing.get_args(_RootType)
        assert len(_ArgListType) == 1, "'params_list.root' must have only one subtype"

        _RequestValidator = _ArgListType[0]
    else:
        assert param_name == "params", "The name of predefined Params must be 'params'"
        _RequestList = None
        _RequestValidator = method.type_hint_dict.get(param_name)

    assert issubclass(_RequestValidator, BaseJsonRpcModel), "'params' must be based on BaseJsonRpcModel"
    param_name_list = list(_RequestValidator.model_fields.keys())

    return _RequestInfo(
        predefined_params=True,
        param_name_list=param_name_list,
        RequestList=_RequestList,
        RequestValidator=_RequestValidator,
    )


@dataclass(frozen=True)
class _RespInfo:
    ReturnType: type
    ReturnValidator: type[BaseModel] | None


def _create_return_validator(method: HttpMethod, is_batch: bool) -> _RespInfo:
    if is_batch:
        _IteratorType = typing.get_origin(method.ReturnType)
        assert issubclass(_IteratorType, collections.abc.AsyncIterator), "Method should return an async iterator"

        _ArgListType = typing.get_args(method.ReturnType)
        assert len(_ArgListType) == 1, "AsyncIterator must have only one subtype"

        _ReturnType = _ArgListType[0]
        _ReturnAnnotation = _ReturnType
    else:
        _ReturnType = method.ReturnType
        _ReturnAnnotation = method.signature.return_annotation
        assert _ReturnAnnotation is not method.signature.empty, "Method must return a value"

    if _is_base_model(method.ReturnType):
        # exclude surplus type conversions
        _ReturnValidator = None
    else:
        _ReturnValidator = pydantic.create_model(
            f"_JsonRpcResp[{method.module}:{method.name}]",
            __module__=method.module,
            __base__=BaseModel,
            result=(_ReturnAnnotation, Field(...)),
        )

    return _RespInfo(_ReturnType, _ReturnValidator)


def _is_base_model(cls: type) -> bool:
    try:
        return issubclass(cls, BaseModel)
    except (BaseException,):
        return False

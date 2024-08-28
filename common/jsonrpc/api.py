from __future__ import annotations

from typing import Literal, Any, Iterator, Iterable, TypeVar

from pydantic import Field
from typing_extensions import Self

from ..http.utils import HttpRequestIdField
from ..utils.pydantic import BaseModel, RootModel

BaseJsonRpcModel = BaseModel


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"]
    id: HttpRequestIdField
    method: str
    params: list = Field(default_factory=list)
    skipCache: bool = True


JsonRpcListItem = TypeVar("JsonRpcListItem")


class JsonRpcListMixin(Iterable[JsonRpcListItem]):
    root: Any

    @property
    def is_list(self) -> bool:
        return isinstance(self.root, list)

    @property
    def is_empty(self) -> bool:
        return self.__len__() == 0

    def __len__(self) -> int:
        if self.root is None:
            return 0
        elif self.is_list:
            return len(self.root)
        return 1

    def __iter__(self) -> Iterator[JsonRpcListItem]:
        if isinstance(self.root, list):
            return iter(self.root)
        elif self.root is None:
            return iter(tuple())

        return iter([self.root])

    def append(self, item) -> None:
        if self.root is None:
            self.root = item
            return

        self.convert_to_list()
        self.root.append(item)

    def convert_to_list(self) -> None:
        if self.is_list:
            return
        elif self.root is None:
            self.root = []
        else:
            self.root = [self.root]


class JsonRpcListRequest(JsonRpcListMixin[JsonRpcRequest], RootModel):
    root: JsonRpcRequest | list[JsonRpcRequest] | None = None


class JsonRpcErrorModel(BaseJsonRpcModel):
    code: int
    message: str
    data: dict | str | None = None


class JsonRpcResp(BaseJsonRpcModel):
    jsonrpc: Literal["2.0"]
    id: HttpRequestIdField
    result: dict | list | str | bool | int | None = None
    error: JsonRpcErrorModel | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_result(self) -> bool:
        return self.result is not None

    def model_post_init(self, _context) -> None:
        if self.is_result and (self.is_error == self.is_result):
            raise ValueError("Response cannot have both 'error' and 'result' fields")

    @property
    def exclude_dict(self) -> dict | set:
        if self.is_error:
            if not self.error.data:
                return {"result": True, "error": {"data": True}}
            else:
                return {"result"}
        return {"error"}

    def model_dump_json(self, *args, **kwargs) -> str:
        kwargs.pop("exclude", None)
        return super().model_dump_json(*args, exclude=self.exclude_dict, **kwargs)


class _JsonRpcRespListDump(RootModel):
    """
    pydantic.RootModel cannot exclude fields if the root has a Union type.
    That is why the implementation is hidden by the Facade.
    """

    root: list[JsonRpcResp]

    def to_json(self) -> str:
        exclude_dict = {idx: r.exclude_dict for idx, r in enumerate(self.root)}
        return super().model_dump_json(exclude=exclude_dict)


class _JsonRpcRespListParser(RootModel):
    """
    pydantic.RootModel cannot exclude fields, if the root has a Union type.
    That is why the implementation is hidden by the Facade.
    """

    root: JsonRpcResp | list[JsonRpcResp] | None = None


class JsonRpcListResp(JsonRpcListMixin[JsonRpcResp]):
    """Facade hides logic for serialization and deserialization."""

    def __init__(self, root: JsonRpcResp | list[JsonRpcResp] | None = None) -> None:
        self.root = root

    @classmethod
    def from_json(cls, json_data: str) -> Self:
        model = _JsonRpcRespListParser.from_json(json_data)
        return JsonRpcListResp(root=model.root)

    def to_json(self) -> str:
        if isinstance(self.root, JsonRpcResp):
            return self.root.to_json()
        elif isinstance(self.root, list):
            model = _JsonRpcRespListDump(root=self.root)
            return model.to_json()
        raise ValueError(f"Wrong root of JsonRpcRespList: {type(self.root).__name__}")

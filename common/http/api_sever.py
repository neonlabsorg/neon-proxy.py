from __future__ import annotations

import abc
import logging
from typing import ClassVar

from typing_extensions import Self

from .server import HttpServer
from .utils import HttpURL, HttpStrOrURL

_LOG = logging.getLogger(__name__)


class BaseApi:
    name: ClassVar[str] = "Unknown"
    __method_list__: list = list()

    def __init__(self) -> None:
        self._server: BaseApiServer | None = None
        # all methods are registered in the class part of parent
        #  here we filter only methods which exist in the API class
        self.__method_list__ = [
            method
            for method in self.__class__.__method_list__
            if method.handler is getattr(self.__class__, method.handler.__name__, None)
        ]

    @property
    def server(self) -> BaseApiServer | None:
        return self._server

    def set_server(self, server: BaseApiServer) -> None:
        assert not self._server
        assert isinstance(server, BaseApiServer)
        self._server = server


class BaseApiServer(HttpServer, abc.ABC):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._url_api_dict: dict[HttpURL, list[BaseApi]] = dict()
        self._virtual_method_name = False

    def add_api(self, api: BaseApi, *, endpoint: HttpStrOrURL = "/") -> Self:
        assert not self._is_started, "Server is already started"

        base_url = HttpURL(endpoint)
        assert not base_url.is_absolute(), "'endpoint' must be relative"
        self._url_api_dict.setdefault(base_url, list()).append(api)

        if not api.server:
            api.set_server(self)
        else:
            assert api.server is self, "Using the same instance API in two different servers isn't allowed"
        return self

    def _validate_unique_method_path(self) -> None:
        assert not self._is_started, "Server is already started"

        # Build the full map of method, and validate uniques of the path
        path_set: set[HttpURL] = set()
        for base_url, api_list in self._url_api_dict.items():
            if self._virtual_method_name and (not base_url.path.endswith("/")):
                base_url = HttpURL(str(base_url.path) + "/")
            for api in api_list:
                for method in api.__method_list__:
                    method_path = base_url.join(HttpURL(method.name))
                    if method_path in path_set:
                        raise KeyError(f"The path {method_path} is already registered")
                    path_set.add(method_path)
                    _LOG.info("register the method %s from API %s", method_path, api.name)

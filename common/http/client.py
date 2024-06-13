from __future__ import annotations

import asyncio
import itertools
import logging
import random
from dataclasses import dataclass
from typing import Sequence

import aiohttp.client as _cl
from typing_extensions import Self

from .utils import HttpURL, HttpStrOrURL
from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..utils.cached import cached_property

_LOG = logging.getLogger(__name__)

HttpClientSession = _cl.ClientSession
HttpClientTimeout = _cl.ClientTimeout
_HttpResponseError = _cl.ClientResponseError


@dataclass
class HttpClientRequest:
    data: str
    header_dict: dict[str, str]
    path: HttpURL | None

    base_url: HttpURL | None = None
    url: HttpURL | None = None

    def build_url(self, base_url: HttpURL) -> Self:
        if base_url == self.base_url:
            return self

        self.base_url = base_url
        self.url = base_url.join(self.path) if self.path else base_url


class HttpClient:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(self._cfg)
        self._base_url_list: list[HttpURL] = list()
        self._timeout = HttpClientTimeout(60)
        self._is_started = False
        self._is_stopped = False
        self._raise_for_status = True
        self._max_retry_cnt = -1
        self._header_dict = {"Content-Type": "application/json; charset=utf-8"}

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_exc_info) -> None:
        await self.stop()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        self._is_stopped = True
        if self._is_started:
            await self.session.close()
            self._is_started = False

    @cached_property
    def session(self) -> HttpClientSession:
        self._is_started = True
        return HttpClientSession(base_url=None, timeout=self._timeout)

    def set_timeout_sec(self, timeout_sec: float) -> Self:
        assert not self._is_started
        self._timeout = HttpClientTimeout(total=timeout_sec)
        return self

    def set_max_retry_cnt(self, max_retry_cnt: int) -> Self:
        self._max_retry_cnt = max_retry_cnt
        return self

    def connect(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        path: str | None = None,
        base_url: HttpStrOrURL | None = None,
        base_url_list: Sequence[HttpStrOrURL] | None = None,
    ) -> Self:
        if host is not None:
            assert base_url is None, "'host' cannot be mixed with 'base_url'"
            assert base_url_list is None, "'host' cannot be mixed with 'base_url_list'"

            path = path or ""
            assert not HttpURL(path).is_absolute(), "'path' cannot be an absolute"

            self._connect_to_url(HttpURL.build(scheme="http", host=host, port=port, path=path))
        elif base_url is not None:
            assert host is None, "'base_url' cannot be mixed with 'host'"
            assert port is None, "'base_url' cannot be mixed with 'port' "
            assert not path, "'base_url' cannot be mixed with 'path'"
            assert base_url_list is None, "'base_url' cannot be mixed with 'base_url_list'"

            self._connect_to_url(HttpURL(base_url))
        else:
            assert base_url_list is not None, "method must have parameters"
            assert host is None, "'base_url_list' cannot be mixed with 'host'"
            assert port is None, "'base_url_list' cannot be mixed with 'host'"
            assert not path, "'base_url_list' cannot be mixed with 'path'"

            for base_url in base_url_list:
                self._connect_to_url(HttpURL(base_url))

        return self

    def _connect_to_url(self, base_url: HttpURL):
        assert base_url.is_absolute(), "'base_url' must be absolute"

        _LOG.debug("connect to the URL: %s", str(base_url), extra=self._msg_filter)
        self._base_url_list.append(base_url)

    async def _send_post_request(self, data: str, *, path: HttpURL | None = None) -> str:
        assert len(self._base_url_list), "HttpClient must have at least one remote URL"

        request = HttpClientRequest(
            data=data,
            header_dict=self._header_dict,
            path=path,
        )
        return await _send_post_request(self, request)

    def _exception_handler(self, request: HttpClientRequest, retry: int, exc: BaseException) -> None:
        """Exception handler for send request.
        Can reraise the exception if it's needed.
        By default, output to logs the exception message.
        """

        msg = dict(
            message="error on retry {Retry} on request to {Path}: {Error}",
            Retry=retry,
            Path=str(request.url),
            Error=str(exc),
        )
        _LOG.warning(msg, extra=self._msg_filter)

        if 0 < self._max_retry_cnt <= retry:
            _LOG.error("reach maximum %d retries, force to stop...", self._max_retry_cnt)
            raise


async def _send_post_request(self: HttpClient, req: HttpClientRequest) -> str:
    base_url_list = self._base_url_list.copy()
    random.shuffle(base_url_list)
    base_url_list = itertools.cycle(base_url_list)
    for retry in itertools.count():
        if self._is_stopped:
            break

        base_url = next(base_url_list)
        req.build_url(base_url)

        try:
            if req.data:
                resp = await self.session.post(req.url, data=req.data, headers=req.header_dict)
            else:
                resp = await self.session.get(req.url, headers=req.header_dict)

            if self._raise_for_status:
                resp.raise_for_status()
            return await resp.text()
        except BaseException as exc:
            # Can reraise exception inside
            self._exception_handler(req, retry, exc)

        await asyncio.sleep(1)
        if retry > 0:
            _LOG.debug("attempt %d to repeat...", retry + 1)

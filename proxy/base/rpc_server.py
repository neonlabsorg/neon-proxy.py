import abc
import logging
from typing import Callable, ClassVar
from typing_extensions import Self

from common.config.config import Config
from common.http.errors import HttpRouteError
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import JsonRpcListRequest, JsonRpcListResp, JsonRpcRequest, JsonRpcResp
from common.jsonrpc.server import JsonRpcApi, JsonRpcServer
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel
from common.stat.api import RpcCallData
from common.utils.cached import ttl_cached_method
from common.utils.json_logger import logging_context, log_msg
from ..base.mp_client import MempoolClient
from ..stat.client import StatClient

_LOG = logging.getLogger(__name__)


class RpcServer(JsonRpcServer):
    _stat_name: ClassVar[str] = "UNKNOWN"

    def __init__(self, cfg: Config, mp_client: MempoolClient, stat_client: StatClient) -> None:
        super().__init__(cfg)
        self._mp_client = mp_client
        self._stat_client = stat_client

    @classmethod
    @abc.abstractmethod
    def endpoint_list(cls) -> list[str]: ...

    def _add_api(self, api: JsonRpcApi) -> Self:
        _LOG.info(log_msg(f"Adding API {api.name}"))

        for endpoint in self.endpoint_list():
            _LOG.info(log_msg(f"Adding API {api.name} to endpoint {endpoint}"))
            super().add_api(api, endpoint=endpoint)
        return self

    async def on_request_list(self, ctx: HttpRequestCtx, request: JsonRpcListRequest) -> None:
        await self._validate_chain_id(ctx)
        with logging_context(ctx=ctx.ctx_id):
            _LOG.info(log_msg("handle BIG request <<< {IP} size={Size}", IP=ctx.ip_addr, Size=len(request.root)))

    async def _validate_chain_id(self, ctx: HttpRequestCtx) -> None:
        NeonProg.validate_protocol()

        if not getattr(ctx, "_chain_id", None):
            await self._set_chain_id(ctx)

    async def _set_chain_id(self, ctx: HttpRequestCtx) -> int:
        evm_cfg = await self.get_evm_cfg()
        if not (token_name := ctx.request.path_params.get("token", "").strip().upper()):
            chain_id = evm_cfg.default_chain_id
            ctx.set_property_value("is_default_chain_id", True)
        elif token := evm_cfg.token_dict.get(token_name, None):
            chain_id = token.chain_id
            ctx.set_property_value("is_default_chain_id", token.is_default)
        else:
            raise HttpRouteError()

        ctx.set_property_value("_chain_id", chain_id)
        return chain_id

    @ttl_cached_method(ttl_sec=1)
    async def get_evm_cfg(self) -> EvmConfigModel:
        # forwarding request to mempool allows to limit the number of requests to Solana to maximum 1 time per second
        # for details, see the mempool_server::get_evm_cfg() implementation
        evm_cfg = await self._mp_client.get_evm_cfg()
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.version)
        return evm_cfg

    def on_response_list(self, ctx: HttpRequestCtx, resp: JsonRpcListResp) -> None:
        with logging_context(ctx=ctx.ctx_id, chain_id=ctx.chain_id):
            msg = log_msg(
                "done BIG request >>> {IP} size={Size} resp_time={TimeMS} msec",
                IP=ctx.ip_addr,
                Size=len(resp),
                TimeMS=ctx.process_time_msec,
            )
            _LOG.info(msg)

        stat = RpcCallData(service=self._stat_name, method="BIG", time_nsec=ctx.process_time_nsec, is_error=False)
        self._stat_client.commit_rpc_call(stat)

    def on_bad_request(self, ctx: HttpRequestCtx) -> None:
        _LOG.warning(log_msg("BAD request from {IP} with size {Size}", IP=ctx.ip_addr, Size=len(ctx.request.body)))

        stat = RpcCallData(service=self._stat_name, method="UNKNOWN", time_nsec=ctx.process_time_nsec, is_error=True)
        self._stat_client.commit_rpc_call(stat)

    async def handle_request(
        self,
        ctx: HttpRequestCtx,
        request: JsonRpcRequest,
        handler: Callable,
    ) -> JsonRpcResp:
        await self._validate_chain_id(ctx)

        info = dict(IP=ctx.ip_addr, ReqID=request.id, Method=request.method)
        with logging_context(ctx=ctx.ctx_id, chain_id=ctx.chain_id):
            _LOG.info(log_msg("handle request <<< {IP} req={ReqID} {Method} {Params}", Params=request.params, **info))

            resp = await handler(ctx, request)
            if resp.is_error:
                msg = log_msg(
                    "error on request >>> {IP} req={ReqID} {Method} {Error} resp_time={TimeMS} msec",
                    Error=resp.error,
                    **info,
                )
            else:
                msg = log_msg(
                    "done request >>> {IP} req={ReqID} {Method} {Result} resp_time={TimeMS} msec",
                    Result=resp.result,
                    **info,
                )
            _LOG.info(dict(**msg, TimeMS=ctx.process_time_msec))

            stat = RpcCallData(
                service=self._stat_name,
                method=request.method,
                time_nsec=ctx.process_time_nsec,
                is_error=resp.is_error,
            )
            self._stat_client.commit_rpc_call(stat)

        return resp

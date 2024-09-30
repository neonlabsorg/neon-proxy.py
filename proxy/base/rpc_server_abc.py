from __future__ import annotations

import abc
import asyncio
import hashlib
import logging
from typing import Callable, ClassVar

from typing_extensions import Self

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddress
from common.http.errors import HttpRouteError
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import JsonRpcListRequest, JsonRpcListResp, JsonRpcRequest, JsonRpcResp
from common.jsonrpc.server import JsonRpcApi, JsonRpcServer
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel, TokenModel
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.stat.api import RpcCallData
from common.utils.cached import ttl_cached_method, cached_property
from common.utils.json_logger import logging_context, log_msg
from common.utils.process_pool import ProcessPool
from indexer.db.indexer_db_client import IndexerDbClient
from .mp_api import MpGasPriceModel, MpRecentGasPricesModel, MpTokenGasPriceModel
from ..base.mp_client import MempoolClient
from ..stat.client import StatClient

_LOG = logging.getLogger(__name__)


class BaseRpcServerComponent:
    def __init__(self, server: BaseRpcServerAbc) -> None:
        self._server = server

    @cached_property
    def _cfg(self) -> Config:
        return self._server._cfg  # noqa

    @cached_property
    def _core_api_client(self) -> CoreApiClient:
        return self._server._core_api_client  # noqa

    @cached_property
    def _sol_client(self) -> SolClient:
        return self._server._sol_client  # noqa

    @cached_property
    def _mp_client(self) -> MempoolClient:
        return self._server._mp_client  # noqa

    @cached_property
    def _db(self) -> IndexerDbClient:
        return self._server._db  # noqa

    @cached_property
    def _msg_filter(self) -> LogMsgFilter:
        return self._server._msg_filter  # noqa

    def _is_default_chain_id(self, ctx: HttpRequestCtx) -> bool:
        return self._server.is_default_chain_id(ctx)

    def _get_ctx_id(self, ctx: HttpRequestCtx) -> str:
        return self._server.get_ctx_id(ctx)

    def _get_chain_id(self, ctx: HttpRequestCtx) -> int:
        return self._server.get_chain_id(ctx)

    async def _get_evm_cfg(self) -> EvmConfigModel:
        return await self._server.get_evm_cfg()

    async def _get_token_gas_price(self, ctx: HttpRequestCtx) -> tuple[MpGasPriceModel, MpTokenGasPriceModel]:
        return await self._server.get_token_gas_price(ctx)

    async def _has_fee_less_tx_permit(
        self,
        ctx: HttpRequestCtx,
        sender: EthAddress,
        contract: EthAddress,
        tx_nonce: int,
        tx_gas_limit: int,
    ) -> bool:
        return await self._server.has_fee_less_tx_permit(ctx, sender, contract, tx_nonce, tx_gas_limit)


class BaseRpcServerAbc(JsonRpcServer, abc.ABC):
    _stat_name: ClassVar[str] = "UNKNOWN"

    class _ProcessPool(ProcessPool):
        def __init__(self, server: BaseRpcServerAbc) -> None:
            super().__init__()
            self._server = server

        def _on_process_start(self, idx: int) -> None:
            self._server._on_process_start(idx)

        def _on_process_stop(self) -> None:
            self._server._on_process_stop()
            self._server = None

    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        stat_client: StatClient,
        db: IndexerDbClient,
    ) -> None:
        super().__init__(cfg)
        self._idx = -1
        self._core_api_client = core_api_client
        self._sol_client = sol_client
        self._mp_client = mp_client
        self._stat_client = stat_client
        self._db = db
        self._process_pool = self._ProcessPool(self)

        self._default_chain_id: int = 0
        self._token_dict: dict[str, TokenModel] = dict()

    def start(self) -> None:
        self._register_handler_list()
        self._process_pool.start()

    def stop(self) -> None:
        self._process_pool.stop()

    @staticmethod
    def get_ctx_id(ctx: HttpRequestCtx) -> str:
        if ctx_id := ctx.get_property_value("ctx_id", None):
            return ctx_id

        size = len(ctx.request.body)
        raw_value = f"{ctx.ip_addr}:{size}:{ctx.start_time_nsec}"
        ctx_id = hashlib.md5(bytes(raw_value, "utf-8")).hexdigest()[:8]
        ctx.set_property_value("ctx_id", ctx_id)
        return ctx_id

    @staticmethod
    def get_chain_id(ctx: HttpRequestCtx) -> int:
        chain_id = ctx.get_property_value("chain_id", None)
        assert chain_id is not None
        return chain_id

    @staticmethod
    def is_default_chain_id(ctx: HttpRequestCtx) -> bool:
        return ctx.get_property_value("is_default_chain_id", False)

    @ttl_cached_method(ttl_sec=1)
    async def get_evm_cfg(self) -> EvmConfigModel:
        # forwarding request to mempool allows to limit the number of requests to Solana to maximum 1 time per second
        # for details, see the mempool_server::get_evm_cfg() implementation
        evm_cfg = await self._mp_client.get_evm_cfg()
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.version)
        return evm_cfg

    async def on_request_list(self, ctx: HttpRequestCtx, request: JsonRpcListRequest) -> None:
        chain_id = await self._validate_chain_id(ctx)
        with logging_context(ctx=self.get_ctx_id(ctx), chain_id=chain_id):
            _LOG.info(log_msg("handle BIG request <<< {IP} size={Size}", IP=ctx.ip_addr, Size=len(request.root)))

    def on_response_list(self, ctx: HttpRequestCtx, resp: JsonRpcListResp) -> None:
        with logging_context(ctx=self.get_ctx_id(ctx), chain_id=self.get_chain_id(ctx)):
            msg = log_msg(
                "done BIG request >>> {IP} size={Size} resp_time={TimeMS} msec",
                IP=ctx.ip_addr,
                Size=len(resp),
                TimeMS=ctx.process_time_msec,
            )
            _LOG.info(msg)

        stat = RpcCallData(service=self._stat_name, method="BIG", time_nsec=ctx.process_time_nsec)
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
        chain_id = await self._validate_chain_id(ctx)

        info = dict(IP=ctx.ip_addr, ReqID=request.id, Method=request.method)
        with logging_context(ctx=self.get_ctx_id(ctx), chain_id=chain_id):
            # _LOG.info(log_msg("handle request <<< {IP} req={ReqID} {Method} {Params}", Params=request.params, **info))

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
            # _LOG.info(dict(**msg, TimeMS=ctx.process_time_msec))

            stat = RpcCallData(
                service=self._stat_name,
                method=request.method,
                time_nsec=ctx.process_time_nsec,
                is_error=resp.is_error,
            )
            self._stat_client.commit_rpc_call(stat)

        return resp

    @ttl_cached_method(ttl_sec=15)
    async def get_gas_price(self) -> MpGasPriceModel:
        # for details, see the mempool_server::get_gas_price() implementation
        gas_price = await self._mp_client.get_gas_price()
        if gas_price.is_empty:
            raise EthError(message="Failed to calculate gas price. Try again later")
        return gas_price

    async def get_token_gas_price(self, ctx: HttpRequestCtx) -> tuple[MpGasPriceModel, MpTokenGasPriceModel]:
        gas_price = await self.get_gas_price()
        chain_id = self.get_chain_id(ctx)
        if not (token_price := gas_price.chain_dict.get(chain_id, None)):
            raise HttpRouteError()
        return gas_price, token_price

    async def get_recent_gas_prices_list(self, ctx: HttpRequestCtx) -> MpRecentGasPricesModel:
        return await self._mp_client.get_recent_gas_prices_list(self.get_ctx_id(ctx), self.get_chain_id(ctx))

    @abc.abstractmethod
    async def has_fee_less_tx_permit(
        self,
        ctx: HttpRequestCtx,
        sender: EthAddress,
        contract: EthAddress,
        tx_nonce: int,
        tx_gas_limit: int,
    ) -> bool: ...

    # protected:

    def _on_process_start(self, idx: int) -> None:
        self._idx = idx
        super().start()

    def _on_process_stop(self) -> None:
        super().stop()

    async def _validate_chain_id(self, ctx: HttpRequestCtx) -> int:
        NeonProg.validate_protocol()
        if chain_id := ctx.get_property_value("chain_id", None):
            return chain_id
        return await self._set_chain_id(ctx)

    async def _set_chain_id(self, ctx: HttpRequestCtx) -> int:
        if not self._default_chain_id:
            await self._refresh_token_dict()

        if not (token_name := ctx.request.path_params.get("token", "").strip().upper()):
            chain_id = self._default_chain_id
            ctx.set_property_value("is_default_chain_id", True)
        elif token := self._token_dict.get(token_name, None):
            chain_id = token.chain_id
            ctx.set_property_value("is_default_chain_id", token.is_default)
        else:
            await self._refresh_token_dict()
            raise HttpRouteError()

        ctx.set_property_value("chain_id", chain_id)
        return chain_id

    async def _refresh_token_dict(self) -> None:
        evm_cfg = await self.get_evm_cfg()
        if not evm_cfg.default_chain_id:
            raise HttpRouteError()

        self._default_chain_id = evm_cfg.default_chain_id
        self._token_dict = evm_cfg.token_dict

    def _add_api(self, api: JsonRpcApi) -> Self:
        _LOG.info(log_msg(f"adding API {api.name}"))

        for endpoint in self._get_endpoint_list():
            _LOG.info(log_msg(f"adding API {api.name} to endpoint {endpoint}"))
            super().add_api(api, endpoint=endpoint)
        return self

    @classmethod
    @abc.abstractmethod
    def _get_endpoint_list(cls) -> list[str]: ...

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            self._db.start(),
            self._stat_client.start(),
            self._mp_client.start(),
            self._sol_client.start(),
            self._core_api_client.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            self._mp_client.stop(),
            self._core_api_client.stop(),
            self._sol_client.stop(),
            self._stat_client.stop(),
            self._db.stop(),
        )

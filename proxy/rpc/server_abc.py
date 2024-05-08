from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Callable

from typing_extensions import Self

from common.config.config import Config
from common.config.utils import LogMsgFilter
from common.ethereum.commit_level import EthCommit
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddress
from common.http.errors import HttpRouteError
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import JsonRpcListRequest, JsonRpcListResp, JsonRpcRequest, JsonRpcResp
from common.jsonrpc.server import JsonRpcApi, JsonRpcServer
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property, ttl_cached_method
from common.utils.json_logger import logging_context, log_msg
from gas_tank.db.gas_less_accounts_db import GasLessAccountDb
from indexer.db.indexer_db_client import IndexerDbClient
from .api import RpcBlockRequest
from ..base.mp_api import MpGasPriceModel, MpTokenGasPriceModel
from ..base.mp_client import MempoolClient

_ENDPOINT_LIST = ("/solana", "/solana/:token", "/", "/:token")
_LOG = logging.getLogger(__name__)


class NeonProxyComponent:
    def __init__(self, server: NeonProxyAbc) -> None:
        super().__init__()
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

    @staticmethod
    def get_ctx_id(ctx: HttpRequestCtx) -> str:
        ctx_id = getattr(ctx, "ctx_id", None)
        assert ctx_id is not None
        return ctx_id

    @staticmethod
    def get_chain_id(ctx: HttpRequestCtx) -> int:
        chain_id = getattr(ctx, "chain_id", None)
        assert chain_id is not None
        return chain_id

    @staticmethod
    def is_default_chain_id(ctx: HttpRequestCtx) -> bool:
        return getattr(ctx, "is_default_chain_id", False)

    async def get_evm_cfg(self) -> EvmConfigModel:
        return await self._server.get_evm_cfg()

    async def get_gas_price(self) -> MpGasPriceModel:
        return await self._server.get_gas_price()

    async def get_token_gas_price(self, ctx: HttpRequestCtx) -> tuple[MpGasPriceModel, MpTokenGasPriceModel]:
        gas_price = await self.get_gas_price()
        token_price = gas_price.chain_dict.get(getattr(ctx, "chain_id"), None)
        if token_price is None:
            raise HttpRouteError()
        return gas_price, token_price

    async def get_block_by_tag(self, block_tag: RpcBlockRequest) -> NeonBlockHdrModel:
        if block_tag.is_block_hash:
            return await self._db.get_block_by_hash(block_tag.block_hash)
        elif block_tag.is_block_number:
            return await self._db.get_block_by_slot(block_tag.block_number)

        block_name = block_tag.block_name
        if block_name == EthCommit.Pending:
            block = await self._db.get_latest_block()
            return block.to_pending()
        elif block_name == EthCommit.Latest:
            return await self._db.get_latest_block()
        elif block_name in (EthCommit.Safe, EthCommit.Finalized):
            return await self._db.get_finalized_block()
        elif block_name == EthCommit.Earliest:
            return await self._db.get_earliest_block()
        raise EthError(f"Unknown block tag {block_name}")

    async def has_fee_less_tx_permit(
        self,
        ctx: HttpRequestCtx,
        sender: EthAddress,
        contract: EthAddress,
        tx_nonce: int,
        tx_gas_limit: int,
    ) -> bool:
        if not self.is_default_chain_id(ctx):
            return False
        gas_tank = self._server._gas_tank  # noqa
        return await gas_tank.has_fee_less_tx_permit(sender, contract, tx_nonce, tx_gas_limit)


class NeonProxyApi(NeonProxyComponent, JsonRpcApi):
    def __init__(self, server: NeonProxyAbc) -> None:
        JsonRpcApi.__init__(self)
        NeonProxyComponent.__init__(self, server)


class NeonProxyAbc(JsonRpcServer):
    def __init__(
        self,
        cfg: Config,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        mp_client: MempoolClient,
        db: IndexerDbClient,
        gas_tank: GasLessAccountDb,
    ) -> None:
        super().__init__(cfg)

        self._core_api_client = core_api_client
        self._sol_client = sol_client
        self._mp_client = mp_client
        self._db = db
        self._gas_tank = gas_tank

    async def on_server_start(self) -> None:
        await asyncio.gather(
            self._db.start(),
            self._gas_tank.start(),
            self._mp_client.start(),
            self._sol_client.start(),
            self._core_api_client.start(),
        )

    async def on_server_stop(self) -> None:
        await asyncio.gather(
            self._gas_tank.close(),
            self._mp_client.close(),
            self._core_api_client.close(),
            self._sol_client.close(),
            self._db.close(),
        )

    def _add_api(self, api: NeonProxyApi) -> Self:
        for endpoint in _ENDPOINT_LIST:
            super().add_api(api, endpoint=endpoint)
        return self

    @ttl_cached_method(ttl_sec=1)
    async def get_evm_cfg(self) -> EvmConfigModel:
        # forwarding request to mempool allows to limit the number of requests to Solana to maximum 1 time per second
        # for details, see the mempool_server::get_evm_cfg() implementation
        evm_cfg = await self._mp_client.get_evm_cfg()
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.protocol_version)
        return evm_cfg

    @ttl_cached_method(ttl_sec=1)
    async def get_gas_price(self) -> MpGasPriceModel:
        # for details, see the mempool_server::get_gas_price() implementation
        gas_price = await self._mp_client.get_gas_price()
        if gas_price.is_empty:
            raise EthError(message="Failed to calculate gas price. Try again later")
        return gas_price

    @staticmethod
    def get_ctx_id(ctx: HttpRequestCtx) -> str:
        if ctx_id := getattr(ctx, "ctx_id", None):
            return ctx_id

        size = len(ctx.request.body)
        raw_value = f"{ctx.ip_addr}:{size}:{ctx.start_time_nsec}"
        ctx_id = hashlib.md5(bytes(raw_value, "utf-8")).hexdigest()[:8]
        ctx.set_property_value("ctx_id", ctx_id)
        return ctx_id

    async def _validate_chain_id(self, ctx: HttpRequestCtx) -> None:
        NeonProg.validate_protocol()

        if not getattr(ctx, "chain_id", None):
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

        ctx.set_property_value("chain_id", chain_id)
        return chain_id

    async def on_request_list(self, ctx: HttpRequestCtx, request: JsonRpcListRequest) -> None:
        await self._validate_chain_id(ctx)
        with logging_context(ctx=self.get_ctx_id(ctx)):
            _LOG.info(log_msg("handle BIG request <<< {IP} size={Size}", IP=ctx.ip_addr, Size=len(request.root)))

    def on_response_list(self, ctx: HttpRequestCtx, resp: JsonRpcListResp) -> None:
        with logging_context(ctx=self.get_ctx_id(ctx)):
            msg = log_msg(
                "done BIG request >>> {IP} size={Size} resp_time={TimeMS} msec",
                IP=ctx.ip_addr,
                Size=len(resp),
                TimeMS=ctx.process_time_msec,
            )
            _LOG.info(msg)

    def on_bad_request(self, ctx: HttpRequestCtx) -> None:
        _LOG.warning(log_msg("BAD request from {IP} with size {Size}", IP=ctx.ip_addr, Size=len(ctx.request.body)))

    async def handle_request(
        self,
        ctx: HttpRequestCtx,
        request: JsonRpcRequest,
        handler: Callable,
    ) -> JsonRpcResp:
        await self._validate_chain_id(ctx)

        info = dict(IP=ctx.ip_addr, ReqID=request.id, Method=request.method)
        with logging_context(ctx=self.get_ctx_id(ctx)):
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
        return resp

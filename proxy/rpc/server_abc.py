from __future__ import annotations

import asyncio
import base58
import logging
from typing import Final, ClassVar

from common.config.config import Config
from common.config.constants import (
    MAINNET_PROGRAM_ID,
    MAINNET_GENESIS_HASH,
    MAINNET_GENESIS_TIME,
    DEVNET_PROGRAM_ID,
    DEVNET_GENESIS_TIME,
    DEVNET_GENESIS_HASH,
    UNKNOWN_GENESIS_HASH,
)
from common.config.utils import LogMsgFilter
from common.ethereum.commit_level import EthCommit
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddress, EthBlockHash
from common.http.errors import HttpRouteError
from common.http.utils import HttpRequestCtx
from common.jsonrpc.server import JsonRpcApi
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.neon.block import NeonBlockHdrModel
from common.solana.commit_level import SolCommit
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property, ttl_cached_method
from common.utils.process_pool import ProcessPool
from gas_tank.db.gas_less_accounts_db import GasLessAccountDb
from indexer.db.indexer_db_client import IndexerDbClient
from .api import RpcBlockRequest
from ..base.mp_api import MpGasPriceModel, MpTokenGasPriceModel
from ..base.mp_client import MempoolClient
from ..base.rpc_server import RpcServer
from ..stat.client import StatClient

_ENDPOINT_LIST = ["/solana", "/solana/:token", "/", "/:token"]
_LOG = logging.getLogger(__name__)


class NeonProxyComponent:
    def __init__(self, server: NeonProxyAbc) -> None:
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
            block = await self._db.get_block_by_hash(block_tag.block_hash)
        elif block_tag.is_block_number:
            if block_tag.block_number == 0:
                block = self._server.genesis_block
            else:
                block = await self._db.get_block_by_slot(block_tag.block_number)
        else:
            block_name = block_tag.block_name
            if block_name == EthCommit.Pending:
                block = await self._db.get_latest_block()
                block = block.to_pending()
            elif block_name == EthCommit.Latest:
                block = await self._db.get_latest_block()
            elif block_name in (EthCommit.Safe, EthCommit.Finalized):
                block = await self._db.get_finalized_block()
            elif block_name == EthCommit.Earliest:
                block = await self._db.get_earliest_block()
            else:
                raise EthError(f"Unknown block tag {block_name}")

        if block.slot == 1:
            genesis_block = self._server.genesis_block
            block = block.to_genesis_child(genesis_block.block_hash)

        return block

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


class NeonProxyAbc(RpcServer):
    _stat_name: ClassVar[str] = "PublicRpc"

    class _ProcessPool(ProcessPool):
        def __init__(self, server: NeonProxyAbc) -> None:
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
        gas_tank: GasLessAccountDb,
    ) -> None:
        super().__init__(cfg, mp_client, stat_client)

        self._idx = -1
        self._core_api_client = core_api_client
        self._sol_client = sol_client
        self._db = db
        self._gas_tank = gas_tank
        self._genesis_block: NeonBlockHdrModel | None = None
        self._process_pool = self._ProcessPool(self)

    @classmethod
    def endpoint_list(cls) -> list[str]:
        return _ENDPOINT_LIST

    async def _on_server_start(self) -> None:
        try:
            if not self._idx:
                self._db.enable_debug_query()

            await asyncio.gather(
                self._db.start(),
                self._stat_client.start(),
                self._gas_tank.start(),
                self._mp_client.start(),
                self._sol_client.start(),
                self._core_api_client.start(),
            )
            await self._init_genesis_block()
        except BaseException as exc:
            _LOG.error("error on start public RPC", exc_info=exc, extra=self._msg_filter)

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            self._gas_tank.stop(),
            self._mp_client.stop(),
            self._core_api_client.stop(),
            self._sol_client.stop(),
            self._db.stop(),
        )

    @property
    def genesis_block(self) -> NeonBlockHdrModel:
        return self._genesis_block

    @ttl_cached_method(ttl_sec=1)
    async def get_gas_price(self) -> MpGasPriceModel:
        # for details, see the mempool_server::get_gas_price() implementation
        gas_price = await self._mp_client.get_gas_price()
        if gas_price.is_empty:
            raise EthError(message="Failed to calculate gas price. Try again later")
        return gas_price

    async def _init_genesis_block(self) -> None:
        parent_hash: Final[EthBlockHash] = EthBlockHash.from_raw(b"\0" * 32)

        if NeonProg.ID == MAINNET_PROGRAM_ID:
            block_hash = EthBlockHash.from_raw(base58.b58decode(MAINNET_GENESIS_HASH))
            block_time = MAINNET_GENESIS_TIME
        elif NeonProg.ID == DEVNET_PROGRAM_ID:
            block_hash = EthBlockHash.from_raw(base58.b58decode(DEVNET_GENESIS_HASH))
            block_time = DEVNET_GENESIS_TIME
        else:
            block = await self._sol_client.get_block(0, SolCommit.Confirmed)
            if block.is_empty:
                block_hash = EthBlockHash.from_raw(base58.b58decode(UNKNOWN_GENESIS_HASH))
                block_time = MAINNET_GENESIS_TIME
            else:
                block_hash = EthBlockHash.from_raw(block.block_hash.to_bytes())
                block_time = block.block_time

        self._genesis_block = NeonBlockHdrModel(
            slot=0,
            commit=EthCommit.Finalized,
            block_hash=block_hash,
            block_time=block_time,
            parent_slot=0,
            parent_block_hash=parent_hash,
        )

        if not self._idx:
            _LOG.debug("genesis hash %s, genesis time %s", block_hash, block_time)

    def start(self) -> None:
        self._register_handler_list()
        self._process_pool.start()

    def stop(self) -> None:
        self._process_pool.stop()

    def _on_process_start(self, idx: int) -> None:
        self._idx = idx
        super().start()

    def _on_process_stop(self) -> None:
        super().stop()

from __future__ import annotations

import abc
import logging
from typing import Final

import base58

from common.config.config import Config
from common.config.constants import (
    MAINNET_PROGRAM_ID,
    MAINNET_GENESIS_TIME,
    MAINNET_GENESIS_HASH,
    DEVNET_PROGRAM_ID,
    DEVNET_GENESIS_HASH,
    DEVNET_GENESIS_TIME,
    ROLLUP_PROGRAM_ID,
    ROLLUP_GENESIS_HASH,
    ROLLUP_GENESIS_TIME,
    UNKNOWN_GENESIS_HASH,
)
from common.ethereum.commit_level import EthCommit
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddress, EthBlockHash
from common.http.utils import HttpRequestCtx
from common.jsonrpc.server import JsonRpcApi
from common.neon.block import NeonBlockHdrModel
from common.neon.cu_price_data_model import CuPricePercentilesModel
from common.neon.neon_program import NeonProg
from common.neon_rpc.client import CoreApiClient
from common.solana.commit_level import SolCommit
from common.solana_rpc.client import SolClient
from gas_tank.db.gas_less_accounts_db import GasLessAccountDb
from indexer.db.indexer_db_client import IndexerDbClient
from .api import RpcBlockRequest
from ..base.mp_api import MpGasPriceModel
from ..base.mp_client import MempoolClient
from ..base.rpc_server_abc import BaseRpcServerAbc, BaseRpcServerComponent
from ..stat.client import StatClient

_LOG = logging.getLogger(__name__)


class NeonProxyComponent(BaseRpcServerComponent):
    def __init__(self, server: NeonProxyAbc) -> None:
        super().__init__(server)
        self._server = server

    async def get_gas_price(self) -> MpGasPriceModel:
        return await self._server.get_gas_price()

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


class NeonProxyApi(NeonProxyComponent, JsonRpcApi):
    def __init__(self, server: NeonProxyAbc) -> None:
        JsonRpcApi.__init__(self)
        NeonProxyComponent.__init__(self, server)


class NeonProxyAbc(BaseRpcServerAbc, abc.ABC):
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
        super().__init__(cfg, core_api_client, sol_client, mp_client, stat_client, db)
        self._gas_tank = gas_tank
        self._genesis_block: NeonBlockHdrModel | None = None

    @property
    def genesis_block(self) -> NeonBlockHdrModel:
        return self._genesis_block

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
        return await self._gas_tank.has_fee_less_tx_permit(sender, contract, tx_nonce, tx_gas_limit)

    async def _init_genesis_block(self) -> None:
        parent_hash: Final[EthBlockHash] = EthBlockHash.from_raw(b"\0" * 32)

        if NeonProg.ID == MAINNET_PROGRAM_ID:
            block_hash = EthBlockHash.from_raw(base58.b58decode(MAINNET_GENESIS_HASH))
            block_time = MAINNET_GENESIS_TIME
        elif NeonProg.ID == DEVNET_PROGRAM_ID:
            block_hash = EthBlockHash.from_raw(base58.b58decode(DEVNET_GENESIS_HASH))
            block_time = DEVNET_GENESIS_TIME
        elif NeonProg.ID == ROLLUP_PROGRAM_ID:
            block_hash = EthBlockHash.from_raw(base58.b58decode(ROLLUP_GENESIS_HASH))
            block_time = ROLLUP_GENESIS_TIME
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
            cu_price_data=CuPricePercentilesModel.default(),
        )

        if not self._idx:
            _LOG.debug("genesis hash %s, genesis time %s", block_hash, block_time)

    async def _on_server_start(self) -> None:
        try:
            await super()._on_server_start()
            await self._gas_tank.start()
            await self._init_genesis_block()
        except BaseException as exc:
            _LOG.error("error on start public RPC", exc_info=exc, extra=self._msg_filter)

    async def _on_server_stop(self) -> None:
        try:
            await self._gas_tank.stop()
            await super()._on_server_stop()
        except BaseException as exc:
            _LOG.error("error on stop public RPC", exc_info=exc, extra=self._msg_filter)

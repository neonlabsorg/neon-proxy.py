from __future__ import annotations

import asyncio
from typing_extensions import Final

from common.config.config import Config
from common.db.constant_db import ConstantDb
from common.db.db_connect import DbConnection
from common.ethereum.hash import EthBlockHash, EthAddress, EthHash32, EthTxHash
from common.neon.account import NeonAccount
from common.neon.block import NeonBlockHdrModel
from common.neon.evm_log_decoder import NeonTxEventModel
from common.neon.transaction_decoder import SolNeonTxIxMetaModel, SolNeonAltTxIxModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.solana.signature import SolTxSigSlotInfo
from .indexer_db import IndexerDbSlotRange
from .neon_tx_db import BlockFeeGasData, NeonTxDb
from .neon_tx_log_db import NeonTxLogDb
from .solana_alt_tx_db import SolAltTxDb
from .solana_block_db import SolBlockDb, SolSlotRange
from .solana_neon_tx_db import SolNeonTxDb
from .solana_tx_cost_db import SolTxCostDb
from .stuck_alt_db import StuckNeonAltDb
from .stuck_neon_tx_db import StuckNeonTxDb


class IndexerDbClient:
    def __init__(self, cfg: Config, db_conn: DbConnection, slot_range=IndexerDbSlotRange()) -> None:
        self._cfg = cfg
        self._db_conn = db_conn

        self._start_slot_name: Final = slot_range.start_slot_name
        self._latest_slot_name: Final = slot_range.latest_slot_name
        self._finalized_slot_name: Final = slot_range.finalized_slot_name

        self._constant_db = ConstantDb(db_conn)
        self._sol_block_db = SolBlockDb(db_conn)
        self._sol_tx_cost_db = SolTxCostDb(db_conn)
        self._neon_tx_db = NeonTxDb(db_conn)
        self._sol_neon_tx_db = SolNeonTxDb(db_conn)
        self._neon_tx_log_db = NeonTxLogDb(db_conn)
        self._sol_alt_tx_db = SolAltTxDb(db_conn)
        self._stuck_neon_tx_db = StuckNeonTxDb(db_conn)
        self._stuck_neon_alt_db = StuckNeonAltDb(db_conn)

        self._db_list = (
            self._constant_db,
            self._sol_block_db,
            self._sol_tx_cost_db,
            self._neon_tx_db,
            self._sol_neon_tx_db,
            self._neon_tx_log_db,
            self._sol_alt_tx_db,
            self._stuck_neon_tx_db,
            self._stuck_neon_alt_db,
        )

    def enable_debug_query(self) -> None:
        self._db_conn.enable_debug_query()

    async def start(self) -> None:
        await self._db_conn.start()
        await asyncio.gather(*[db.start() for db in self._db_list])

    async def stop(self) -> None:
        await self._db_conn.stop()

    async def get_earliest_slot(self) -> int:
        return await self._constant_db.get_int(None, self._start_slot_name, 0)

    async def get_latest_slot(self) -> int:
        return await self._constant_db.get_int(None, self._latest_slot_name, 0)

    async def get_finalized_slot(self) -> int:
        return await self._constant_db.get_int(None, self._finalized_slot_name, 0)

    async def get_block_by_slot(self, slot: int) -> NeonBlockHdrModel:
        slot_range = await self._get_slot_range()
        return await self._sol_block_db.get_block_by_slot(None, slot, slot_range)

    async def get_block_by_hash(self, block_hash: EthBlockHash) -> NeonBlockHdrModel:
        slot_range = await self._get_slot_range()
        return await self._sol_block_db.get_block_by_hash(None, block_hash, slot_range)

    async def get_earliest_block(self) -> NeonBlockHdrModel:
        slot_range = await self._get_slot_range()
        return await self._sol_block_db.get_block_by_slot(None, slot_range.earliest_slot, slot_range)

    async def get_latest_block(self) -> NeonBlockHdrModel:
        slot_range = await self._get_slot_range()
        return await self._sol_block_db.get_block_by_slot(None, slot_range.latest_slot, slot_range)

    async def get_finalized_block(self) -> NeonBlockHdrModel:
        slot_range = await self._get_slot_range()
        return await self._sol_block_db.get_block_by_slot(None, slot_range.finalized_slot, slot_range)

    async def get_historical_base_fees(self, chain_id: int, num_blocks: int, latest_slot: int) -> list[BlockFeeGasData]:
        return await self._neon_tx_db.get_base_fee_list(None, chain_id, num_blocks, latest_slot)

    async def get_historical_priority_fees(self, num_blocks: int) -> list[list[int]]:
        return await self._sol_block_db.get_cu_price_percentile_list(None, num_blocks)

    async def _get_slot_range(self) -> SolSlotRange:
        slot_list = await self._constant_db.get_int_list(
            None,
            key_list=tuple([self._start_slot_name, self._finalized_slot_name, self._latest_slot_name]),
            default=0,
        )
        return SolSlotRange(*slot_list)

    async def get_event_list(
        self,
        from_block: int | None,
        to_block: int | None,
        address_list: tuple[EthAddress, ...],
        topic_list: tuple[tuple[EthHash32, ...], ...],
    ) -> tuple[NeonTxEventModel, ...]:
        return await self._neon_tx_log_db.get_event_list(None, from_block, to_block, address_list, topic_list)

    async def get_tx_list_by_slot(self, slot: int) -> tuple[NeonTxMetaModel, ...]:
        return await self._neon_tx_db.get_tx_list_by_slot(None, slot)

    async def get_tx_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_tx_hash(None, neon_tx_hash)

    async def get_tx_by_sender_nonce(
        self,
        sender: NeonAccount,
        tx_nonce: int,
        inc_no_chain_id: bool,
    ) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_sender_nonce(None, sender, tx_nonce, inc_no_chain_id)

    async def get_tx_by_slot_tx_idx(self, slot: int, tx_idx: int) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_slot_tx_idx(None, slot, tx_idx)

    async def get_sol_tx_sig_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> tuple[SolTxSigSlotInfo, ...]:
        return await self._sol_neon_tx_db.get_sol_tx_sig_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_alt_sig_list_by_neon_sig(self, neon_tx_hash: EthTxHash) -> tuple[SolTxSigSlotInfo, ...]:
        return await self._sol_alt_tx_db.get_alt_sig_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_sol_ix_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> tuple[SolNeonTxIxMetaModel, ...]:
        return await self._sol_neon_tx_db.get_sol_ix_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_alt_ix_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> tuple[SolNeonAltTxIxModel, ...]:
        return await self._sol_alt_tx_db.get_alt_ix_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_stuck_neon_tx_list(self) -> tuple[int | None, tuple[dict, ...]]:
        return await self._stuck_neon_tx_db.get_obj_list(None, False)

    async def get_stuck_neon_alt_list(self) -> tuple[int | None, tuple[dict, ...]]:
        return await self._stuck_neon_alt_db.get_obj_list(None, True)

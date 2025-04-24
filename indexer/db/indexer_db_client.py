from __future__ import annotations

import asyncio
from typing import Sequence, Final

from common.config.config import Config
from common.db.constant_db import ConstantDb
from common.db.db_connect import DbConnection, DbTxCtx
from common.ethereum.hash import EthBlockHash, EthAddress, EthHash32, EthTxHash
from common.neon.address import NeonAddress
from common.neon.block import NeonBlockHdrModel, NeonBlockCuPriceInfo, NeonBlockBaseFeeInfo
from common.neon.evm_log_decoder import NeonTxEventModel
from common.neon.transaction_decoder import SolNeonTxIxMetaModel, SolNeonAltTxIxModel
from common.neon.transaction_meta_model import NeonTxMetaModel
from common.neon.transaction_model import NeonSkdTxModel, NeonTxModel
from common.solana.pubkey import SolPubKey
from common.solana.signature import SolTxSigSlotInfo, SolTxSig
from .indexer_db import IndexerDbSlotRange
from .neon_block_fee_db import NeonBlockFeeDB
from .neon_skd_tx_body_db import NeonSkdTxBodyDb
from .neon_skd_tx_db import NeonSkdTxDb
from .neon_skd_tx_relation_db import NeonSkdTxRelationDb
from .neon_skd_tx_sig_db import NeonSkdTxSigDb
from .neon_skd_tx_status_db import NeonSkdTxStatusDb
from .neon_tx_db import NeonTxDb
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
        self._neon_block_fee_db = NeonBlockFeeDB(db_conn)
        self._sol_tx_cost_db = SolTxCostDb(db_conn)
        self._neon_skd_tx_db = NeonSkdTxDb(db_conn)
        self._neon_skd_tx_body_db = NeonSkdTxBodyDb(db_conn)
        self._neon_skd_tx_sig_db = NeonSkdTxSigDb(db_conn)
        self._neon_skd_tx_status_db = NeonSkdTxStatusDb(db_conn)
        self._neon_skd_tx_relation_db = NeonSkdTxRelationDb(db_conn)
        self._neon_tx_db = NeonTxDb(db_conn, self._neon_skd_tx_sig_db, self._neon_skd_tx_relation_db)
        self._sol_neon_tx_db = SolNeonTxDb(db_conn)
        self._neon_tx_log_db = NeonTxLogDb(db_conn)
        self._sol_alt_tx_db = SolAltTxDb(db_conn)
        self._stuck_neon_tx_db = StuckNeonTxDb(db_conn)
        self._stuck_neon_alt_db = StuckNeonAltDb(db_conn)

        self._db_list = (
            self._constant_db,
            self._sol_block_db,
            self._neon_block_fee_db,
            self._sol_tx_cost_db,
            self._neon_skd_tx_db,
            self._neon_skd_tx_body_db,
            self._neon_skd_tx_sig_db,
            self._neon_skd_tx_status_db,
            self._neon_skd_tx_relation_db,
            self._neon_tx_db,
            self._sol_neon_tx_db,
            self._neon_tx_log_db,
            self._sol_alt_tx_db,
            self._stuck_neon_tx_db,
            self._stuck_neon_alt_db,
        )

        self._skd_tree_db_list = (
            self._neon_skd_tx_db,
            self._neon_skd_tx_body_db,
            self._neon_skd_tx_sig_db,
            self._neon_skd_tx_status_db,
            self._neon_skd_tx_relation_db,
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

    async def get_block_base_fee_list(
        self, chain_id: int, block_cnt: int, latest_slot: int
    ) -> Sequence[NeonBlockBaseFeeInfo]:
        return await self._neon_block_fee_db.get_block_base_fee_list(None, chain_id, block_cnt, latest_slot)

    async def get_block_cu_price_list(
        self, block_cnt: int, latest_slot: int | None = None
    ) -> Sequence[NeonBlockCuPriceInfo]:
        if latest_slot is None:
            latest_slot = await self.get_latest_slot()
        return await self._sol_block_db.get_block_cu_price_list(None, block_cnt, latest_slot)

    async def _get_slot_range(self) -> SolSlotRange:
        slot_list = await self._constant_db.get_int_list(
            None,
            key_list=tuple([self._start_slot_name, self._finalized_slot_name, self._latest_slot_name]),
            default=0,
        )
        return SolSlotRange(*slot_list)

    async def get_event_list(
        self,
        from_slot: int | None,
        to_slot: int | None,
        address_list: Sequence[EthAddress],
        topic_list: Sequence[Sequence[EthHash32]],
    ) -> Sequence[NeonTxEventModel]:
        return await self._neon_tx_log_db.get_event_list(None, from_slot, to_slot, address_list, topic_list)

    async def get_tx_list_by_slot(self, slot: int) -> Sequence[NeonTxMetaModel]:
        return await self._neon_tx_db.get_tx_list_by_slot(None, slot)

    async def get_tx_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_tx_hash(None, neon_tx_hash)

    async def get_tx_by_sender_nonce(
        self,
        sender: NeonAddress,
        tx_nonce: int,
        tx_index: int,
        inc_no_chain_id: bool,
    ) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_sender_nonce(None, sender, tx_nonce, tx_index, inc_no_chain_id)

    async def get_tx_by_slot_tx_idx(self, slot: int, tx_idx: int) -> NeonTxMetaModel | None:
        return await self._neon_tx_db.get_tx_by_slot_tx_idx(None, slot, tx_idx)

    async def get_sol_tx_sig_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> Sequence[SolTxSigSlotInfo]:
        return await self._sol_neon_tx_db.get_sol_tx_sig_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_alt_sig_list_by_neon_sig(self, neon_tx_hash: EthTxHash) -> Sequence[SolTxSigSlotInfo]:
        return await self._sol_alt_tx_db.get_alt_sig_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_sol_ix_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> Sequence[SolNeonTxIxMetaModel]:
        return await self._sol_neon_tx_db.get_sol_ix_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_neon_tx_hash_by_sol_tx_sig(self, sol_tx_sig: SolTxSig) -> EthTxHash:
        return await self._sol_neon_tx_db.get_neon_tx_hash_by_sol_tx_sig(None, sol_tx_sig)

    async def get_alt_ix_list_by_neon_tx_hash(self, neon_tx_hash: EthTxHash) -> Sequence[SolNeonAltTxIxModel]:
        return await self._sol_alt_tx_db.get_alt_ix_list_by_neon_tx_hash(None, neon_tx_hash)

    async def get_stuck_neon_tx_list(self) -> tuple[int | None, Sequence[dict]]:
        return await self._stuck_neon_tx_db.get_obj_list(None, False)

    async def get_stuck_neon_alt_list(self) -> tuple[int | None, Sequence[dict]]:
        return await self._stuck_neon_alt_db.get_obj_list(None, True)

    async def get_neon_skd_tx_list(self, slot: int, limit: int) -> Sequence[NeonSkdTxModel]:
        return await self._neon_skd_tx_db.get_tx_list(None, slot, limit)

    async def get_old_neon_skd_tx_list_by_slot(self, min_slot: int, limit: int) -> Sequence[NeonSkdTxModel]:
        return await self._neon_skd_tx_db.get_old_tx_list_by_slot(None, min_slot, limit)

    async def get_neon_skd_tx_by_hash(self, neon_tx_hash: EthTxHash) -> NeonSkdTxModel | None:
        return await self._neon_skd_tx_db.get_tx_by_hash(None, neon_tx_hash)

    async def get_neon_skd_tx_holder_address(self, neon_tx_hash: EthTxHash) -> SolPubKey | None:
        return await self._neon_skd_tx_status_db.get_holder_address(None, neon_tx_hash)

    async def commit_neon_skd_tx(self, slot: int, tree_address: SolPubKey, neon_tx: NeonTxModel) -> None:
        async def _tx(ctx: DbTxCtx) -> None:
            await self._neon_skd_tx_body_db.commit_tx(ctx, slot, tree_address, neon_tx)
            await self._neon_skd_tx_sig_db.commit_tx(ctx, slot, tree_address, neon_tx)
            await self._neon_skd_tx_db.commit_tx(ctx, slot, tree_address, neon_tx)
            if (neon_tx.index != 0) and (await self._neon_skd_tx_db.get_top_tx(ctx, tree_address)):
                return

            # if no a top transaction -> insert it -> for correct destroying of tree accounts
            rand_tx_hash = bytes().join(
                [
                    b"\xff\xff\xff\xff\xff\xff",
                    neon_tx.neon_tx_hash.to_bytes()[6:]
                ]
            )
            idx_info = dict(neon_tx_hash=EthTxHash.from_raw(rand_tx_hash), index=0, rlp_tx=bytes())
            top_neon_tx = neon_tx.model_copy(update=idx_info)

            await self._neon_skd_tx_db.commit_tx(ctx, slot, tree_address, top_neon_tx)
            await self._neon_skd_tx_sig_db.commit_tx(ctx, slot, tree_address, top_neon_tx)

        await self._db_conn.run_tx(_tx)

    async def destroy_tree_account(self, tree_address: SolPubKey) -> None:
        tree_addr_list = [tree_address]
        await asyncio.gather(*[db.destroy_tree_list(None, tree_addr_list) for db in self._skd_tree_db_list])

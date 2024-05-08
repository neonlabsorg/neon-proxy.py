import asyncio

from common.config.config import Config
from common.ethereum.hash import EthTxHash
from common.neon_rpc.api import HolderAccountStatus
from common.neon_rpc.client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from ..base.objects import NeonIndexedBlockInfo, NeonIndexedHolderInfo, NeonIndexedTxInfo


class StuckObjectValidator:
    def __init__(self, cfg: Config, sol_client: SolClient, core_api_client: CoreApiClient) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._core_api_client = core_api_client
        self._last_slot = 0

    async def validate_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        slot = neon_block.slot
        last_slot = slot - self._cfg.stuck_object_validate_blockout
        if last_slot < self._last_slot:
            return
        elif self._last_slot == 0:
            self._last_slot = slot
            return
        elif neon_block.stuck_slot > neon_block.slot:
            self._last_slot = slot
            return

        self._last_slot = slot
        neon_block.check_stuck_objs(self._cfg)

        task_list = list()
        failed_holder_list: list[NeonIndexedHolderInfo] = list()
        for holder in neon_block.iter_stuck_neon_holder():
            if holder.last_slot > last_slot:
                pass
            task_list.append(self._validate_holder(holder, failed_holder_list))

        failed_tx_list: list[NeonIndexedTxInfo] = list()
        for tx in neon_block.iter_stuck_neon_tx():
            if tx.last_slot > last_slot:
                continue
            task_list.append(self._validate_tx(tx, failed_tx_list))

        await asyncio.gather(*task_list)
        neon_block.fail_neon_holder_list(failed_holder_list)
        neon_block.fail_neon_tx_list(failed_tx_list)

    async def _validate_tx(self, tx: NeonIndexedTxInfo, failed_tx_list: list) -> None:
        if not await self._is_valid_holder(tx.holder_address, tx.neon_tx_hash):
            failed_tx_list.append(tx)

    async def _validate_holder(self, holder: NeonIndexedHolderInfo, failed_holder_list: list) -> None:
        if not await self._is_valid_holder(holder.address, holder.neon_tx_hash):
            failed_holder_list.append(holder)

    async def _is_valid_holder(self, address: SolPubKey, neon_tx_hash: EthTxHash) -> bool:
        holder = await self._core_api_client.get_holder_account(address)
        if holder.is_empty:
            return False
        return (holder.neon_tx_hash, holder.status) == (neon_tx_hash, HolderAccountStatus.Active)

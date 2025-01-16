import logging
from typing import Generator, Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.neon.skd_tree import NeonSkdTreeAddress
from common.neon.transaction_model import NeonSkdTxModel, NeonSkdTxStatus
from common.neon_rpc.api import NeonSkdTreeModel, NeonSkdTreeNodeModel
from common.solana.pubkey import SolPubKey
from common.solana_rpc.ws_client import SolWatchAccountSession
from common.utils.cached import cached_property, cached_method
from .server_abc import ExecutorServerAbc, ExecutorComponent

_LOG = logging.getLogger(__name__)


class NeonSkdTreeParser(ExecutorComponent):
    _recheck_sec: Final[float] = ONE_BLOCK_SEC * 3

    def __init__(self, server: ExecutorServerAbc, payer: NeonAddress, nonce: int) -> None:
        super().__init__(server)
        self._payer = payer
        self._nonce = nonce

        self._tree: NeonSkdTreeModel | None = None
        self._neon_tx_hash = EthTxHash.default()

        self._watch_session = SolWatchAccountSession(self._cfg, self._sol_client, force_check_sec=self._recheck_sec)

    async def start(self) -> None:
        await self._watch_session.subscribe_account(self.address)
        await self._refresh()

    async def stop(self) -> None:
        await self._watch_session.disconnect()

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self._neon_tx_hash

    @property
    def payer(self) -> NeonAddress:
        return self._payer

    @property
    def chain_id(self) -> int:
        return self._payer.chain_id

    @cached_property
    def address(self) -> SolPubKey:
        return NeonSkdTreeAddress.from_raw(self._payer, self._nonce).address

    async def _refresh(self) -> None:
        await self._watch_session.update()

        if not self._watch_session.pop_changed_key_list():
            return

        self._tree = await self._core_api_client.get_neon_skd_tree(self._payer, self._nonce)
        if self._tree.node_list and self._neon_tx_hash.is_empty:
            self._neon_tx_hash = self._tree.node_list[0].neon_tx_hash

        _LOG.debug(
            "NeonSkdTree %s for payer %s has status %s, txs %d",
            self.address,
            self._tree.payer,
            self._tree.status,
            len(self._tree.node_list),
        )

    @cached_method
    async def _get_slot_out(self) -> int:
        evm_cfg = await self._get_evm_cfg()
        return evm_cfg.tree_account_slot_out

    async def can_be_destroyed(self) -> bool:
        await self._refresh()

        if not self._tree.is_exist:
            return True
        elif (status := self._tree.active_status) == NeonSkdTxStatus.InProgress:
            return False
        elif status != status.NotStarted:
            return True

        slot = await self._sol_client.get_slot()
        slot_out = await self._get_slot_out()
        return self._tree.is_destroyable(slot, slot_out)

    async def is_exist(self) -> bool:
        await self._refresh()
        return self._tree.is_exist

    async def is_started(self) -> bool:
        await self._refresh()
        return self._tree.is_started

    async def iter_neon_skd_tx_list(self) -> Generator[tuple[NeonSkdTxStatus, NeonSkdTxModel], None, None]:
        await self._refresh()

        async def _get_skd_tx(_idx: int, _node: NeonSkdTreeNodeModel) -> NeonSkdTxModel | None:
            _skd_tx = await self._db.get_neon_skd_tx_by_hash(_node.neon_tx_hash)
            return _skd_tx if _skd_tx and _skd_tx.rlp_tx else None

        for idx, node in enumerate(self._tree.node_list):
            if (node.parent_cnt == 0) and (node.status in (node.status.NotStarted, node.status.InProgress)):
                if skd_tx := await _get_skd_tx(idx, node):
                    yield node.status, skd_tx

    async def get_neon_skd_status(self, index: int) -> NeonSkdTxStatus:
        await self._refresh()
        status = self._tree.get_neon_skd_status(index)
        return status

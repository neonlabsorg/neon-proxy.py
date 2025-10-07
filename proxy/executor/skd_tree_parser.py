import logging
from typing import Final, AsyncGenerator

from common.config.constants import ONE_BLOCK_SEC, ONE_BLOCK_MSEC
from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.neon.neon_program import NeonProg
from common.neon.skd_tree import NeonSkdTreeAddress
from common.neon.transaction_model import NeonSkdTxModel, NeonSkdTxStatus
from common.neon_rpc.api import NeonSkdTreeModel, NeonSkdTreeNodeModel
from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_property, ttl_cached_method
from .server_abc import ExecutorServerAbc, ExecutorComponent

_LOG = logging.getLogger(__name__)


class NeonSkdTreeParser(ExecutorComponent):
    _ReCheckSec: Final[float] = ONE_BLOCK_SEC * 3

    def __init__(self, server: ExecutorServerAbc, payer: NeonAddress, nonce: int, root_neon_tx_hash: EthTxHash) -> None:
        super().__init__(server)
        self._payer = payer
        self._nonce = nonce
        self._root_neon_tx_hash = root_neon_tx_hash

        self._tree: NeonSkdTreeModel | None = None

    async def start(self) -> None:
        await self._refresh()

    async def stop(self) -> None: ...

    @cached_property
    def req_id(self) -> dict:
        return dict(root_tx=self._root_neon_tx_hash.ident, skd_tree=self.address.ident)

    @property
    def root_neon_tx_hash(self) -> EthTxHash:
        return self._root_neon_tx_hash

    @property
    def payer(self) -> NeonAddress:
        return self._payer

    @property
    def chain_id(self) -> int:
        return self._payer.chain_id

    @cached_property
    def address(self) -> SolPubKey:
        return NeonSkdTreeAddress.from_raw(self._payer, self._nonce).address

    @ttl_cached_method(ttl_msec=ONE_BLOCK_MSEC)
    async def _refresh(self) -> None:
        self._tree = await self._core_api_client.get_neon_skd_tree(self._payer, self._nonce)
        if not self._tree.is_exist:
            _LOG.debug("NeonSkdTree %s doesn't exist", self.address)
            return

        # It is possible if the transaction is loaded from a stuck holder
        if self._root_neon_tx_hash.is_empty:
            _LOG.debug(
                "NeonSkdTree %s for payer %s:%d -> root-tx-hash %s",
                self.address,
                self._payer,
                self._nonce,
                self._tree.root_neon_tx_hash,
            )
            self._root_neon_tx_hash = self._tree.root_neon_tx_hash

        _LOG.debug(
            "NeonSkdTree %s for payer %s:%d has tx-hash %s, status %s, txs %s",
            self.address,
            self._payer,
            self._nonce,
            self._tree.root_neon_tx_hash,
            self._tree.status,
            tuple([n.status.value for n in self._tree.node_list]),
        )

    async def can_be_destroyed(self) -> bool:
        await self._refresh()

        if not self._is_exist:
            return True
        elif (status := self._tree.active_status) == NeonSkdTxStatus.InProgress:
            return False
        elif status != status.NotStarted:
            return True

        slot = self._slot_session.confirmed_slot
        slot_out = NeonProg.TreeAccountSlotOut
        return self._tree.is_destroyable(slot, slot_out)

    async def is_exist(self) -> bool:
        await self._refresh()
        return self._is_exist

    async def iter_active_neon_skd_tx_list(self) -> AsyncGenerator[tuple[NeonSkdTxStatus, NeonSkdTxModel], None]:
        await self._refresh()

        async def get_skd_tx(node_: NeonSkdTreeNodeModel) -> NeonSkdTxModel | None:
            tx = await self._db.get_neon_skd_tx_by_hash(node_.neon_tx_hash)
            return tx if tx and tx.rlp_tx else None

        for idx, node in enumerate(self._tree.node_list):
            if (node.parent_cnt == 0) and (node.status in (node.status.NotStarted, node.status.InProgress)):
                if skd_tx := await get_skd_tx(node):
                    yield node.status, skd_tx

    async def get_neon_skd_status(self, index: int) -> NeonSkdTxStatus:
        await self._refresh()
        return self._tree.get_neon_skd_status(index)

    @property
    def _is_exist(self):
        return self._tree.is_exist and (self._tree.root_neon_tx_hash == self._root_neon_tx_hash)

import logging

from common.config.constants import ONE_BLOCK_MSEC
from common.ethereum.hash import EthTxHash
from common.neon_rpc.api import HolderAccountModel
from common.solana.pubkey import SolPubKey
from common.utils.cached import ttl_cached_method
from .errors import StuckTxError
from .server_abc import ExecutorComponent, ExecutorServerAbc

_LOG = logging.getLogger(__name__)


class HolderAccountValidator(ExecutorComponent):
    def __init__(
        self,
        server: ExecutorServerAbc,
        neon_tx_hash: EthTxHash,
        holder_address: SolPubKey,
        is_stuck_tx: bool,
    ) -> None:
        super().__init__(server)
        self._neon_tx_hash = neon_tx_hash
        self._holder_addr = holder_address
        self._is_stuck_tx = is_stuck_tx

        if not self._holder_addr.is_empty:
            self._holder_acct: HolderAccountModel | None = None
            _LOG.debug("use holder %s", self._holder_addr)
        else:
            self._holder_acct = HolderAccountModel.default()

    @ttl_cached_method(ttl_msec=ONE_BLOCK_MSEC)
    async def _refresh(self) -> None:
        if self._holder_addr.is_empty:
            return

        self._holder_acct = await self._core_api_client.get_holder_account(self._holder_addr)
        if (not self._holder_acct.is_active) or (not self._is_valid):
            return

        _LOG.debug(
            "Holder %s: hash %s, status %s, slot %s, timestamp %s, accounts %d, steps %d, gas_used %d",
            self._holder_addr,
            self._holder_acct.neon_tx_hash,
            self._holder_acct.status.name.upper(),
            self._holder_acct.block.slot,
            self._holder_acct.block.timestamp,
            len(self._holder_acct.account_key_list),
            self._holder_acct.evm_step_cnt,
            self._holder_acct.gas_used,
        )

    @property
    def holder_account(self) -> HolderAccountModel:
        assert self._holder_acct
        return self._holder_acct

    async def validate_no_stuck_tx(self) -> None:
        assert not self._is_stuck_tx

        await self._refresh()
        if self._holder_acct.is_active and (not self._is_valid):
            self._raise_stuck_error()

    async def has_active_stuck_tx(self) -> bool:
        assert self._is_stuck_tx

        await self._refresh()
        return self._is_valid and self._holder_acct.is_active

    async def is_finalized(self) -> bool:
        await self._refresh()

        if self._is_valid:
            return self._holder_acct.is_finalized
        elif self._is_stuck_tx:
            return True
        return False

    async def refresh(self) -> None:
        await self._refresh()

    @property
    def _is_valid(self) -> bool:
        return self._holder_acct.neon_tx_hash == self._neon_tx_hash

    def _raise_stuck_error(self) -> None:
        _LOG.debug(
            "holder %s contains stuck NeonTx %s",
            self._holder_addr,
            self._holder_acct.neon_tx_hash,
        )
        raise StuckTxError(self._holder_acct)

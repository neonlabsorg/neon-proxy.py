import logging
from typing import Final

from common.ethereum.hash import EthTxHash
from common.neon_rpc.api import HolderAccountModel
from common.solana.pubkey import SolPubKey
from common.utils.cached import ttl_cached_method
from .errors import StuckTxError
from .server_abc import ExecutorComponent, ExecutorServerAbc

_LOG = logging.getLogger(__name__)


class HolderAccountValidator(ExecutorComponent):
    _op_resource_pct: Final[int] = 2
    _emul_tx_pct: Final[int] = 10
    _prepare_tx_pct: Final[int] = 20
    _total_exec_pct: Final[int] = 100 - _prepare_tx_pct
    _max_exec_pct: Final[int] = 95  # 100% is on complete tx in mempool

    def __init__(
        self,
        server: ExecutorServerAbc,
        base_tx_hash: EthTxHash,
        neon_tx_hash: EthTxHash,
        holder_address: SolPubKey,
        is_stuck_tx: bool,
    ) -> None:
        super().__init__(server)
        self._base_tx_hash = base_tx_hash
        self._neon_tx_hash = neon_tx_hash
        self._holder_addr = holder_address
        self._is_stuck_tx = is_stuck_tx
        self._base_tx_exec_pct = self._op_resource_pct
        self._tx_exec_pct = 0
        self._emul_step_cnt = 0
        self._holder_acct: HolderAccountModel | None = None

        _LOG.debug("use holder %s", self._holder_addr)

    def mark_complete_prepare(self) -> None:
        if self._base_tx_exec_pct < self._prepare_tx_pct:
            self._base_tx_exec_pct = self._prepare_tx_pct

    def set_emul_step_cnt(self, emul_step_cnt: int) -> None:
        if self._base_tx_exec_pct < self._emul_tx_pct:
            self._base_tx_exec_pct = self._emul_tx_pct
        self._emul_step_cnt = emul_step_cnt

    @ttl_cached_method(ttl_msec=10)
    async def _refresh(self) -> None:
        self._holder_acct = await self._core_api_client.get_holder_account(self._holder_addr)

        if (
            self._holder_acct.is_active or
            (self._holder_acct.is_finalized and self._holder_acct.neon_tx_hash == self._neon_tx_hash)
        ):
            _LOG.debug(
                "holder %s contains NeonTx %s, status %s, slot %s, timestamp %s, accounts %d, steps %d",
                self._holder_addr,
                self._holder_acct.neon_tx_hash,
                self._holder_acct.status.name.upper(),
                self._holder_acct.block.slot,
                self._holder_acct.block.timestamp,
                len(self._holder_acct.account_key_list),
                self._holder_acct.evm_step_cnt,
            )

        # Inform the mempool for the current progress of the transaction execution
        if self._emul_step_cnt:
            tx_exec_pct = self._holder_acct.evm_step_cnt * self._total_exec_pct // self._emul_step_cnt
            tx_exec_pct = max(tx_exec_pct + self._base_tx_exec_pct, self._max_exec_pct)
        else:
            tx_exec_pct = self._base_tx_exec_pct

        if tx_exec_pct <= self._tx_exec_pct:
            return

        self._tx_exec_pct = tx_exec_pct
        await self._mp_client.notify_exec_tx_status(self._base_tx_hash, self._neon_tx_hash, tx_exec_pct)

    @property
    def holder_account(self) -> HolderAccountModel:
        assert self._holder_acct
        return self._holder_acct

    @property
    def is_valid(self) -> bool:
        return self._holder_acct.neon_tx_hash == self._neon_tx_hash

    async def validate_stuck_tx(self) -> None:
        assert not self._is_stuck_tx

        await self._refresh()
        if self._holder_acct.is_active and (not self.is_valid):
            self._raise_stuck_error()

    async def is_active(self) -> bool:
        await self._refresh()

        if not self._holder_acct.is_active:
            return False
        elif not self.is_valid:
            if not self._is_stuck_tx:
                self._raise_stuck_error()
            return False
        return True

    async def is_finalized(self) -> bool:
        await self._refresh()
        is_valid = self.is_valid

        if self._is_stuck_tx:
            return (not is_valid) or self._holder_acct.is_finalized

        if (not is_valid) and self._holder_acct.is_active:
            # strange case, because the holder was tested on the start...
            #  it is possible if the operator-key and the holder-id are defined on two different proxies
            self._raise_stuck_error()

        return is_valid and self._holder_acct.is_finalized

    async def refresh(self) -> None:
        await self._refresh()

    def _raise_stuck_error(self) -> None:
        _LOG.debug(
            "holder %s contains stuck NeonTx %s",
            self._holder_addr,
            self._holder_acct.neon_tx_hash,
        )
        raise StuckTxError(self._holder_acct)

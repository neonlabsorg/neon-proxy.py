import logging

from common.neon_rpc.api import HolderAccountModel
from .errors import StuckTxError
from .transaction_executor_ctx import NeonExecTxCtx

_LOG = logging.getLogger(__name__)


class HolderAccountValidator:
    def __init__(self, ctx: NeonExecTxCtx) -> None:
        self._ctx = ctx
        self._holder_acct: HolderAccountModel | None = None

    async def refresh(self) -> None:
        self._holder_acct = await self._ctx.core_api_client.get_holder_account(self._ctx.holder_address)

        _LOG.debug(
            "holder %s contains NeonTx %s, block %s, time %s, status %s, accounts %d, steps %d",
            self._ctx.holder_address,
            self._holder_acct.neon_tx_hash,
            self._holder_acct.block.slot,
            self._holder_acct.block.timestamp,
            self._holder_acct.status.name.upper(),
            len(self._holder_acct.account_key_list),
            self._holder_acct.evm_step_cnt,
        )

        self._ctx.set_holder_account(self._holder_acct)

    @property
    def holder_account(self) -> HolderAccountModel:
        assert self._holder_acct
        return self._holder_acct

    @property
    def is_valid(self) -> bool:
        return self._holder_acct.neon_tx_hash == self._ctx.neon_tx_hash

    async def validate_stuck_tx(self) -> None:
        assert not self._ctx.is_stuck_tx

        await self.refresh()
        if self._holder_acct.is_active and (not self.is_valid):
            self._raise_stuck_error()

    async def is_active(self) -> bool:
        await self.refresh()

        if not self._holder_acct.is_active:
            return False
        elif not self.is_valid:
            if not self._ctx.is_stuck_tx:
                self._raise_stuck_error()
            return False
        return True

    async def is_finalized(self) -> bool:
        await self.refresh()
        is_valid = self.is_valid

        if self._ctx.is_stuck_tx:
            return (not is_valid) or self._holder_acct.is_finalized

        if (not is_valid) and self._holder_acct.is_active:
            # strange case, because the holder was tested on the start...
            #  it is possible if the operator-key and the holder-id are defined on two different proxies
            self._raise_stuck_error()

        return is_valid and self._holder_acct.is_finalized

    def _raise_stuck_error(self) -> None:
        _LOG.debug(
            "holder %s contains stuck NeonTx %s",
            self._ctx.holder_address,
            self._holder_acct.neon_tx_hash,
        )
        raise StuckTxError(self._holder_acct)

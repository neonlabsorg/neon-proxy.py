import logging
from typing import Sequence

from common.ethereum.errors import EthError
from common.neon.neon_program import NeonEvmIxCode
from common.solana.instruction import SolTxIx
from .strategy_base import BaseTxPrepStage

_LOG = logging.getLogger(__name__)


class NewAccountTxPrepStage(BaseTxPrepStage):
    async def make_ix_list(self) -> Sequence[SolTxIx]:
        if self._is_account_exist:
            return list()

        neon_acct = await self._core_api_client.get_neon_account(self._ctx.sender, None)
        ix = self._ctx.neon_prog.make_create_neon_account_ix(
            neon_acct.neon_address,
            neon_acct.sol_address,
            neon_acct.contract_sol_address,
        )
        return tuple([ix])

    async def prep_execution(self) -> bool:
        return self._is_account_exist

    def _get_ix_name_list(self) -> Sequence[str]:
        if self._is_account_exist:
            return tuple()

        return tuple([NeonEvmIxCode.CreateAccountBalance.name])

    @property
    def _is_account_exist(self) -> bool:
        if self._ctx.is_started_tx or self._ctx.is_scheduled_tx:
            return True

        # valid only for less-fee transactions
        if not self._ctx.has_payer_balance:
            if not self._ctx.holder_tx.is_fee_less:
                raise EthError("insufficient funds")
            return False
        return True

import logging
from typing import ClassVar, Sequence

from common.ethereum.errors import EthError
from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import NeonAccountModel
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_base import BaseTxPrepStage

_LOG = logging.getLogger(__name__)


class NewAccountTxPrepStage(BaseTxPrepStage):
    name: ClassVar[str] = NeonEvmIxCode.CreateAccountBalance.name

    def get_tx_name_list(self) -> Sequence[str]:
        return tuple([self.name])

    async def build_tx_list(self) -> Sequence[Sequence[SolTx]]:
        if self._is_account_exist():
            return list()

        prog = self._ctx.neon_prog
        neon_acct = await self._get_neon_account()
        ix = prog.make_create_neon_account_ix(
            neon_acct.neon_address,
            neon_acct.sol_address,
            neon_acct.contract_sol_address,
        )

        return [[SolLegacyTx(self.name, tuple([ix]))]]

    async def prep_before_exec(self) -> bool:
        return self._is_account_exist()

    def _is_account_exist(self) -> bool:
        if self._ctx.is_stuck_tx or self._ctx.is_scheduled_tx:
            return True

        # valid only for less-fee transactions
        if not self._ctx.has_payer_balance:
            if not self._ctx.holder_tx.is_fee_less:
                raise EthError("insufficient funds")
            return False
        return True

    async def _get_neon_account(self) -> NeonAccountModel:
        return await self._core_api_client.get_neon_account(self._ctx.sender, None)

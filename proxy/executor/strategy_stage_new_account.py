import logging
from typing import ClassVar

from common.ethereum.errors import EthError
from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import NeonAccountModel
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.errors import SolNoMoreRetriesError
from .strategy_base import BaseTxPrepStage

_LOG = logging.getLogger(__name__)


class NewAccountTxPrepStage(BaseTxPrepStage):
    name: ClassVar[str] = NeonEvmIxCode.CreateAccountBalance.name

    def get_tx_name_list(self) -> tuple[str, ...]:
        return tuple([self.name])

    async def build_tx_list(self) -> list[list[SolTx]]:
        if await self._is_account_exist():
            return list()

        prog = self._ctx.neon_prog
        neon_acct = await self._get_neon_account()
        ix = prog.make_create_neon_account_ix(neon_acct.account, neon_acct.sol_address, neon_acct.contract_sol_address)

        return [[SolLegacyTx(self.name, tuple([ix]))]]

    async def update_after_emulation(self) -> bool:
        if not await self._is_account_exist():
            raise SolNoMoreRetriesError()
        return True

    async def _is_account_exist(self) -> bool:
        if self._ctx.is_stuck_tx:
            return True

        # valid only for less-fee transactions
        neon_acct = await self._get_neon_account()
        if not neon_acct.balance:
            if self._ctx.neon_tx.gas_price:
                raise EthError("insufficient funds")
            return False
        return True

    async def _get_neon_account(self) -> NeonAccountModel:
        return await self._ctx.core_api_client.get_neon_account(self._ctx.sender, None)

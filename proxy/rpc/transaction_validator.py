from __future__ import annotations

from common.ethereum.errors import EthError, EthNonceTooLowError, EthWrongChainIdError
from common.http.utils import HttpRequestCtx
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import NeonAccountModel, NeonContractModel
from .server_abc import NeonProxyComponent
from ..base.mp_api import MpTokenGasPriceModel, MpGasPriceModel


class NpTxValidator(NeonProxyComponent):
    _max_u64 = 2**64 - 1
    _max_u256 = 2**256 - 1

    async def validate(self, ctx: HttpRequestCtx, neon_tx: NeonTxModel) -> NeonAccountModel:
        global_price, token_price = await self.get_token_gas_price(ctx)

        chain_id = self._get_chain_id(ctx, neon_tx)
        tx_gas_limit = await self._get_tx_gas_limit(neon_tx)

        sender = NeonAccount.from_raw(neon_tx.from_address, chain_id)
        neon_acct = await self._core_api_client.get_neon_account(sender, None)
        neon_contract = await self._core_api_client.get_neon_contract(sender, None)

        self._prevalidate_sender_eoa(neon_contract)
        self._prevalidate_tx_size(neon_tx)
        self._prevalidate_tx_gas_limit(neon_tx, tx_gas_limit)
        await self._prevalidate_tx_gas_price(ctx, token_price, neon_tx)
        self._prevalidate_underpriced_tx_wo_chain_id(global_price, neon_tx)
        self._prevalidate_sender_balance(neon_tx, neon_acct, tx_gas_limit)
        self._validate_nonce(neon_tx, neon_acct.state_tx_cnt)

        return neon_acct

        chain_id = ctx.chain_id
        tx_chain_id = neon_tx.chain_id
        if not tx_chain_id:
            if not self.is_default_chain_id(ctx):
                raise EthWrongChainIdError()
        elif tx_chain_id != chain_id:
            raise EthWrongChainIdError()
        return chain_id

    async def _get_tx_gas_limit(self, neon_tx: NeonTxModel) -> int:
        if neon_tx.has_chain_id or neon_tx.call_data.is_empty:
            return neon_tx.gas_limit

        evm_cfg = await self.get_evm_cfg()
        tx_gas_limit = neon_tx.gas_limit * evm_cfg.gas_limit_multiplier_wo_chain_id
        return min(self._max_u64, tx_gas_limit)

    @staticmethod
    def _prevalidate_sender_eoa(neon_contract: NeonContractModel) -> None:
        if neon_contract.has_code:
            raise EthError(message="sender not an eoa")

    @staticmethod
    def _prevalidate_tx_size(neon_tx: NeonTxModel):
        if len(neon_tx.call_data) > (127 * 1024):
            raise EthError(message="transaction size is too big")

    def _prevalidate_tx_gas_limit(self, neon_tx: NeonTxModel, tx_gas_limit: int) -> None:
        if tx_gas_limit < 21_000:
            raise EthError(message="gas limit reached")

        if tx_gas_limit > self._max_u64:
            raise EthError(message="gas uint64 overflow")
        if (tx_gas_limit * neon_tx.gas_price) > self._max_u256:
            raise EthError(message="max fee per gas higher than 2^256-1")

    async def _prevalidate_tx_gas_price(
        self,
        ctx: HttpRequestCtx,
        token_price: MpTokenGasPriceModel,
        neon_tx: NeonTxModel,
    ) -> None:
        # Operator can set minimum gas price to accept txs into mempool
        min_gas_price = token_price.min_acceptable_gas_price
        if neon_tx.gas_price >= min_gas_price:
            return

        # Fee-less transaction
        if not neon_tx.gas_price:
            has_fee_less_permit = await self.has_fee_less_tx_permit(
                ctx, neon_tx.from_address, neon_tx.to_address, neon_tx.nonce, neon_tx.gas_limit
            )
            if has_fee_less_permit:
                return

        if neon_tx.has_chain_id:
            raise EthError(f"transaction underpriced: have {neon_tx.gas_price} want {min_gas_price}")

    @staticmethod
    def _prevalidate_underpriced_tx_wo_chain_id(global_price: MpGasPriceModel, neon_tx: NeonTxModel) -> None:
        if neon_tx.has_chain_id:
            return
        elif neon_tx.gas_price >= global_price.min_wo_chain_id_acceptable_gas_price:
            return

        raise EthError("proxy configuration doesn't allow underpriced transaction without chain-id")

    @staticmethod
    def _prevalidate_sender_balance(neon_tx: NeonTxModel, neon_account: NeonAccountModel, tx_gas_limit: int):
        user_balance = neon_account.balance
        required_balance = neon_tx.gas_price * tx_gas_limit + neon_tx.value

        if required_balance <= user_balance:
            return

        if neon_tx.call_data.is_empty:
            message = "insufficient funds for transfer"
        else:
            message = "insufficient funds for gas * price + value"

        raise EthError(f"{message}: address {neon_account.address} have {user_balance} want {required_balance}")

    def _validate_nonce(self, neon_tx: NeonTxModel, state_tx_cnt: int) -> None:
        tx_sender = neon_tx.from_address
        tx_nonce = neon_tx.nonce
        state_tx_cnt = state_tx_cnt

        if self._max_u64 in (state_tx_cnt, tx_nonce):
            raise EthError(
                code=EthNonceTooLowError.CODE,
                message=f"nonce has max value: address {tx_sender}, tx: {tx_nonce} state: {state_tx_cnt}",
            )

        EthNonceTooLowError.raise_if_error(tx_nonce, state_tx_cnt, sender=tx_sender)

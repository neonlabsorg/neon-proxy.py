import logging

from common.ethereum.errors import EthError, EthNonceTooLowError, EthNonceTooHighError, EthWrongChainIdError
from common.ethereum.hash import EthTxHashField, EthTxHash
from common.http.utils import HttpRequestCtx
from common.jsonrpc.errors import InvalidParamError
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import NeonAccountModel, NeonContractModel
from common.utils.json_logger import logging_context
from proxy.base.mp_api import MpTxRespCode, MpTokenGasPriceModel, MpGasPriceModel
from proxy.base.rpc_server_abc import BaseRpcServerComponent

_LOG = logging.getLogger(__name__)


class RpcNeonTxExecutor(BaseRpcServerComponent):
    _max_u64 = 2**64 - 1
    _max_u256 = 2**256 - 1

    async def send_neon_tx(self, ctx: HttpRequestCtx, eth_tx_rlp: bytes) -> EthTxHashField:
        try:
            neon_tx = NeonTxModel.from_raw(eth_tx_rlp, raise_exception=True)
        except EthError:
            raise
        except ValueError:
            # Convert validation errors into proper EthError with a correct error code.
            raise EthError(message="invalid transaction")
        except (BaseException,):
            raise InvalidParamError(message="wrong transaction format")

        tx_id = neon_tx.neon_tx_hash.ident
        with logging_context(tx=tx_id):
            _LOG.debug("sendEthTransaction %s: %s", neon_tx.neon_tx_hash, neon_tx)
            return await self._send_neon_tx_impl(ctx, neon_tx, eth_tx_rlp)

    async def _send_neon_tx_impl(self, ctx: HttpRequestCtx, neon_tx: NeonTxModel, eth_tx_rlp: bytes) -> EthTxHashField:
        try:
            if await self._is_neon_tx_exist(neon_tx.neon_tx_hash):
                return neon_tx.neon_tx_hash

            ctx_id = self._get_ctx_id(ctx)
            sender = await self._validate(ctx, neon_tx)
            chain_id = sender.chain_id

            resp = await self._mp_client.send_raw_transaction(ctx_id, eth_tx_rlp, chain_id, sender.state_tx_cnt)

            if resp.code in (MpTxRespCode.Success, MpTxRespCode.AlreadyKnown):
                return neon_tx.neon_tx_hash
            elif resp.code == MpTxRespCode.NonceTooLow:
                EthNonceTooLowError.raise_error(neon_tx.nonce, resp.state_tx_cnt, sender=sender.address)
            elif resp.code == MpTxRespCode.Underprice:
                raise EthError(message="replacement transaction underpriced")
            elif resp.code == MpTxRespCode.NonceTooHigh:
                raise EthNonceTooHighError.raise_error(neon_tx.nonce, resp.state_tx_cnt, sender=sender.address)
            elif resp.code == MpTxRespCode.UnknownChainID:
                raise EthWrongChainIdError()
            else:
                raise EthError(message="unknown error")

        except BaseException as exc:
            # raise already exists error
            await self._is_neon_tx_exist(neon_tx.neon_tx_hash)

            if not isinstance(exc, EthError):
                _LOG.error("unexpected error on sendRawTransaction", exc_info=exc, extra=self._msg_filter)
            raise

    async def _is_neon_tx_exist(self, tx_hash: EthTxHash) -> bool:
        if tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash):
            if tx_meta.neon_tx_rcpt.slot <= await self._db.get_finalized_slot():
                raise EthError(message="already known")
            return True
        return False

    async def _validate(self, ctx: HttpRequestCtx, neon_tx: NeonTxModel) -> NeonAccountModel:
        global_price, token_price = await self._get_token_gas_price(ctx)

        chain_id = self._validate_chain_id(ctx, neon_tx)
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

    def _validate_chain_id(self, ctx: HttpRequestCtx, neon_tx: NeonTxModel) -> int:
        chain_id = self._get_chain_id(ctx)
        tx_chain_id = neon_tx.chain_id
        if not tx_chain_id:
            if not self._is_default_chain_id(ctx):
                raise EthWrongChainIdError()
        elif tx_chain_id != chain_id:
            raise EthWrongChainIdError()
        return chain_id

    async def _get_tx_gas_limit(self, neon_tx: NeonTxModel) -> int:
        if neon_tx.has_chain_id or neon_tx.call_data.is_empty:
            return neon_tx.gas_limit

        evm_cfg = await self._get_evm_cfg()
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
            has_fee_less_permit = await self._has_fee_less_tx_permit(
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

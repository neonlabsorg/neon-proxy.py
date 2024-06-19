from typing import ClassVar

from common.ethereum.errors import EthError, EthNonceTooLowError, EthNonceTooHighError, EthWrongChainIdError
from common.ethereum.hash import EthAddressField
from common.ethereum.transaction import EthTx, EthTxField
from common.http.utils import HttpRequestCtx
from common.neon.account import NeonAccount
from common.utils.json_logger import logging_context
from .pr_eth_sign_api import PrEthSignApi
from .server_abc import PrivateRpcApi, PrivateRpcServerAbc
from ..base.mp_api import MpTxRespCode


class PrEthTxApi(PrivateRpcApi):
    name: ClassVar[str] = "PrivateRpc::EthTx"

    def __init__(self, server: PrivateRpcServerAbc) -> None:
        super().__init__(server)
        self._sign_api = PrEthSignApi(server)

    @PrivateRpcApi.method(name="eth_sendTransaction")
    async def eth_send_tx(self, ctx: HttpRequestCtx, tx: EthTxField, eth_address: EthAddressField) -> str:
        chain_id = ctx.chain_id

        if (neon_account := NeonAccount.from_raw(eth_address, chain_id)) is None:
            raise EthError(message="signer not found")

        with logging_context(ctx=ctx.ctx_id, chain_id=chain_id):
            signed_tx_hex = await self._sign_api.eth_sign_tx(ctx, tx, eth_address)
            signed_eth_tx = EthTx.from_raw(signed_tx_hex)
            state_tx_cnt = await self._core_api_client.get_state_tx_cnt(neon_account, None)

            send_result = await self._mp_client.send_raw_transaction(
                ctx.ctx_id, signed_eth_tx.to_bytes(), signed_eth_tx.chain_id, state_tx_cnt
            )

            if send_result.code in (MpTxRespCode.Success, MpTxRespCode.AlreadyKnown):
                return signed_tx_hex
            elif send_result.code == MpTxRespCode.NonceTooLow:
                EthNonceTooLowError.raise_error(
                    signed_eth_tx.nonce, send_result.state_tx_cnt, sender=eth_address.to_string()
                )
            elif send_result.code == MpTxRespCode.Underprice:
                raise EthError(message="replacement transaction underpriced")
            elif send_result.code == MpTxRespCode.NonceTooHigh:
                raise EthNonceTooHighError.raise_error(
                    signed_eth_tx.nonce, send_result.state_tx_cnt, sender=eth_address.to_string()
                )
            elif send_result.code == MpTxRespCode.UnknownChainID:
                raise EthWrongChainIdError()
            else:
                raise EthError(message="unknown error")

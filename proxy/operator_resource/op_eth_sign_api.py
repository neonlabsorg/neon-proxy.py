import logging
from typing import ClassVar

from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.utils.json_logger import logging_context
from .server_abc import OpResourceApi
from ..base.op_api import OpSignEthMessageRequest, OpSignEthMessageResp, OpSignEthTxRequest, OpSignEthTxResp

_LOG = logging.getLogger(__name__)


class OpEthSignApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::EthSign"

    @OpResourceApi.method(name="signEthMessage")
    async def sign_eth_message(self, request: OpSignEthMessageRequest) -> OpSignEthMessageResp:
        try:
            with logging_context(ctx=request.ctx_id):
                neon_account = await self._neon_account(request.eth_address)
                signed_message = neon_account.sign_msg(request.data.to_bytes())

                return OpSignEthMessageResp(signed_message=signed_message.to_hex())
        except Exception as exc:
            _LOG.error("Signing message failed", extra=self._msg_filter, exc_info=exc)
            return OpSignEthMessageResp(error="Error signing message")

    @OpResourceApi.method(name="signEthTransaction")
    async def sign_eth_tx(self, request: OpSignEthTxRequest) -> OpSignEthTxResp:
        try:
            with logging_context(ctx=request.ctx_id):
                neon_account = await self._neon_account(request.eth_address)
                signed_tx = neon_account.sign_transaction(request.tx, request.chain_id)

                return OpSignEthTxResp(signed_tx=signed_tx)
        except Exception as exc:
            _LOG.error("Signing transaction failed", extra=self._msg_filter, exc_info=exc)
            return OpSignEthTxResp(error="Error signing transaction")

    async def _neon_account(self, eth_address: EthAddress) -> NeonAccount:
        signers = await self._server.get_signer_list()

        for signer in signers:
            neon_account = NeonAccount.from_private_key(signer.secret, 0)

            if neon_account.eth_address == eth_address:
                return neon_account

        raise LookupError("Signer not found")

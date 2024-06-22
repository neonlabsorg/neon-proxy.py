import logging
from typing import ClassVar

from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .resource_manager import OpResourceMng
from .server_abc import OpResourceApi
from ..base.op_api import OpSignEthMsgRequest, OpSignEthMsgResp, OpSignEthTxRequest, OpSignEthTxResp

_LOG = logging.getLogger(__name__)


class OpEthSignApi(OpResourceApi):
    name: ClassVar[str] = "OpResource::EthSign"

    @OpResourceApi.method(name="signEthMessage")
    async def sign_eth_message(self, request: OpSignEthMsgRequest) -> OpSignEthMsgResp:
        try:
            with logging_context(**request.req_id):
                if not (neon_account := await self._get_neon_account(request.sender, 0)):
                    return OpSignEthMsgResp(signed_msg=bytes(), error=f"Unknown sender {request.sender}")

                signed_msg = neon_account.sign_msg(request.data.to_bytes())
                return OpSignEthMsgResp(signed_msg=signed_msg.to_bytes())
        except Exception as exc:
            _LOG.error("signing message failed", extra=self._msg_filter, exc_info=exc)
            return OpSignEthMsgResp(signed_msg=bytes(), error="Error signing message")

    @OpResourceApi.method(name="signEthTransaction")
    async def sign_eth_tx(self, request: OpSignEthTxRequest) -> OpSignEthTxResp:
        try:
            with logging_context(**request.req_id):
                sender = request.neon_tx.from_address
                if not (neon_account := await self._get_neon_account(sender, request.chain_id)):
                    return OpSignEthTxResp(signed_tx=bytes(), error=f"Unknown sender {sender}")

                signed_tx = neon_account.sign_tx(request.neon_tx)
                return OpSignEthTxResp(signed_tx=signed_tx)
        except Exception as exc:
            _LOG.error("signing transaction failed", extra=self._msg_filter, exc_info=exc)
            return OpSignEthTxResp(signed_tx=bytes(), error="Error signing transaction")

    @cached_property
    def _op_resource_mng(self) -> OpResourceMng:
        return self._server._op_resource_mng  # noqa

    async def _get_neon_account(self, eth_address: EthAddress, chain_id: int) -> NeonAccount | None:
        if not (op_signer := self._op_resource_mng.get_signer_by_eth_address(eth_address)):
            return None

        if op_signer.neon_account.chain_id != chain_id:
            return NeonAccount.from_private_key(op_signer.neon_account.private_key, chain_id)
        return op_signer.neon_account

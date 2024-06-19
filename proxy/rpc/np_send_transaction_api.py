import logging
from typing import ClassVar

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthError, EthNonceTooLowError, EthNonceTooHighError, EthWrongChainIdError
from common.ethereum.hash import EthTxHashField, EthTxHash
from common.http.utils import HttpRequestCtx
from common.jsonrpc.errors import InvalidParamError
from common.neon.transaction_model import NeonTxModel
from common.utils.json_logger import logging_context
from .server_abc import NeonProxyApi
from .transaction_validator import NpTxValidator
from ..base.mp_api import MpTxRespCode

_LOG = logging.getLogger(__name__)


class NpExecTxApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::ExecuteTransaction"

    @property
    def _tx_validator(self) -> NpTxValidator:
        return self._server._tx_validator  # noqa

    @NeonProxyApi.method(name="eth_sendRawTransaction")
    async def send_raw_tx(self, ctx: HttpRequestCtx, raw_tx: EthBinStrField) -> EthTxHashField:
        try:
            eth_tx_rlp = raw_tx.to_bytes()
            neon_tx = NeonTxModel.from_raw(eth_tx_rlp, raise_exception=True)
        except EthError:
            raise
        except (BaseException,):
            raise InvalidParamError(message="wrong transaction format")

        tx_id = neon_tx.neon_tx_hash.to_bytes()[:4].hex()
        with logging_context(tx=tx_id):
            _LOG.debug("sendRawTransaction %s: %s", neon_tx.neon_tx_hash, neon_tx)
            # validate that tx was executed 2 times (second after sending to mempool)
            if await self._is_neon_tx_exist(neon_tx.neon_tx_hash):
                return neon_tx.neon_tx_hash

            try:
                acct = await self._tx_validator.validate(ctx, neon_tx)
                resp = await self._mp_client.send_raw_transaction(
                    ctx.ctx_id, eth_tx_rlp, acct.chain_id, acct.state_tx_cnt
                )

                if resp.code in (MpTxRespCode.Success, MpTxRespCode.AlreadyKnown):
                    return neon_tx.neon_tx_hash
                elif resp.code == MpTxRespCode.NonceTooLow:
                    # revalidate that tx was finalized
                    if await self._is_neon_tx_exist(neon_tx.neon_tx_hash):
                        return neon_tx.neon_tx_hash

                    EthNonceTooLowError.raise_error(neon_tx.nonce, resp.state_tx_cnt, sender=acct.address)
                elif resp.code == MpTxRespCode.Underprice:
                    raise EthError(message="replacement transaction underpriced")
                elif resp.code == MpTxRespCode.NonceTooHigh:
                    raise EthNonceTooHighError.raise_error(neon_tx.nonce, resp.state_tx_cnt, sender=acct.address)
                elif resp.code == MpTxRespCode.UnknownChainID:
                    raise EthWrongChainIdError()
                else:
                    raise EthError(message="unknown error")

            except BaseException as exc:
                if not isinstance(exc, EthError):
                    _LOG.error("unexpected error on eth_sendRawTransaction", exc_info=exc, extra=self._msg_filter)
                raise

    async def _is_neon_tx_exist(self, tx_hash: EthTxHash) -> bool:
        if tx_meta := await self._db.get_tx_by_neon_tx_hash(tx_hash):
            if tx_meta.neon_tx_rcpt.slot <= await self._db.get_finalized_slot():
                raise EthError(message="already known")
            return True
        return False

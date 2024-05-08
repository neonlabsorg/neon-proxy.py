from __future__ import annotations

from common.app_data.client import AppDataClient
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EvmConfigModel
from .mp_api import (
    MP_ENDPOINT,
    MpGasPriceModel,
    MpRequest,
    MpTxCntRequest,
    MpTxCntResp,
    MpTxRequest,
    MpTxResp,
    MpTxModel,
    MpGetTxByHashRequest,
    MpGetTxResp,
    MpGetTxBySenderNonceRequest,
    MpTxPoolContentResp,
)


class MempoolClient(AppDataClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(host="127.0.0.1", port=self._cfg.mp_port, path=MP_ENDPOINT)

    async def get_evm_cfg(self) -> EvmConfigModel:
        return await self._get_evm_cfg()

    async def get_gas_price(self) -> MpGasPriceModel:
        return await self._get_gas_price()

    async def get_pending_tx_cnt(self, ctx_id: str, sender: NeonAccount) -> int | None:
        req = MpTxCntRequest(ctx_id=ctx_id, sender=sender)
        resp = await self._get_pending_tx_cnt(req)
        return resp.tx_cnt

    async def get_mempool_tx_cnt(self, ctx_id: str, sender: NeonAccount) -> int | None:
        req = MpTxCntRequest(ctx_id=ctx_id, sender=sender)
        resp = await self._get_mempool_tx_cnt(req)
        return resp.tx_cnt

    async def send_raw_transaction(
        self, ctx_id: str, eth_tx_rlp: bytes, chain_id: int, state_tx_cnt: int
    ) -> MpTxResp:
        req = MpTxRequest(
            ctx_id=ctx_id,
            tx=MpTxModel.from_raw(eth_tx_rlp, chain_id),
            state_tx_cnt=state_tx_cnt,
        )
        return await self._send_raw_transaction(req)

    async def get_tx_by_hash(self, ctx_id: str, neon_tx_hash: EthTxHash) -> NeonTxModel:
        req = MpGetTxByHashRequest(ctx_id=ctx_id, neon_tx_hash=neon_tx_hash)
        resp = await self._get_tx_by_hash(req)
        return resp.tx

    async def get_tx_by_sender_nonce(self, ctx_id: str, sender: NeonAccount, tx_nonce: int) -> NeonTxModel:
        req = MpGetTxBySenderNonceRequest(ctx_id=ctx_id, sender=sender, tx_nonce=tx_nonce)
        resp = await self._get_tx_by_sender_nonce(req)
        return resp.tx

    async def get_content(self, ctx_id: str) -> MpTxPoolContentResp:
        return await self._get_content(MpRequest(ctx_id=ctx_id))

    @AppDataClient.method(name="getGasPrice")
    async def _get_gas_price(self) -> MpGasPriceModel: ...

    @AppDataClient.method(name="sendRawTransaction")
    async def _send_raw_transaction(self, request: MpTxRequest) -> MpTxResp: ...

    @AppDataClient.method(name="getPendingTransactionByHash")
    async def _get_tx_by_hash(self, request: MpGetTxByHashRequest) -> MpGetTxResp: ...

    @AppDataClient.method(name="getPendingTransactionBySenderNonce")
    async def _get_tx_by_sender_nonce(self, request: MpGetTxBySenderNonceRequest) -> MpGetTxResp: ...

    @AppDataClient.method(name="getEvmConfig")
    async def _get_evm_cfg(self) -> EvmConfigModel: ...

    @AppDataClient.method(name="getPendingTransactionCounter")
    async def _get_pending_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp: ...

    @AppDataClient.method(name="getMempoolTransactionCounter")
    async def _get_mempool_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp: ...

    @AppDataClient.method(name="getMempoolContent")
    async def _get_content(self, request: MpRequest) -> MpTxPoolContentResp: ...

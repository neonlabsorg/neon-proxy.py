from __future__ import annotations

from typing import ClassVar

from common.app_data.client import AppDataClient
from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EvmConfigModel, NeonAccountModel
from common.solana.pubkey import SolPubKey
from common.solana.signature import SolTxSig
from .ex_api import (
    ExecTxDoneCode,
    ExecTxDoneResp,
    ExecTxDoneRequest,
    ExecTxDoneStuckRequest,
    ExecTxDoneStuckResp,
    ExecTxNotifyStatusResp,
    ExecTxNotifyStatusRequest,
)
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
    MpGetTxStatusListBySender,
    MpTxStatusListResp,
)


class MempoolClient(AppDataClient):
    name: ClassVar[str] = "Mempool"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(host=self._cfg.mp_ip, port=self._cfg.mp_port, path=MP_ENDPOINT)

    async def get_evm_cfg(self) -> EvmConfigModel:
        return await self._get_evm_cfg()

    async def get_gas_price(self) -> MpGasPriceModel:
        return await self._get_gas_price()

    async def get_pending_tx_cnt(self, ctx_id: dict, sender: NeonAddress) -> int | None:
        req = MpTxCntRequest(ctx_id=ctx_id, sender=sender)
        resp = await self._get_pending_tx_cnt(req)
        return resp.tx_cnt

    async def get_mempool_tx_cnt(self, ctx_id: dict, sender: NeonAddress) -> int | None:
        req = MpTxCntRequest(ctx_id=ctx_id, sender=sender)
        resp = await self._get_mempool_tx_cnt(req)
        return resp.tx_cnt

    async def send_raw_transaction(self, ctx_id: dict, sender: NeonAccountModel, rlp_tx: bytes) -> MpTxResp:
        req = MpTxRequest(
            ctx_id=ctx_id,
            tx=MpTxModel.from_param(rlp_tx, sender.chain_id, SolTxSig.default(), SolPubKey.default()),
            state_tx_cnt=sender.state_tx_cnt,
            balance=sender.balance,
        )
        return await self._send_raw_transaction(req)

    async def notify_exec_tx_status(
        self,
        base_tx_hash: EthTxHash,
        neon_tx_hash: EthTxHash,
        tx_exec_pct: int,
    ) -> ExecTxNotifyStatusResp:
        req = ExecTxNotifyStatusRequest(base_tx_hash=base_tx_hash, neon_tx_hash=neon_tx_hash, exec_pct=tx_exec_pct)
        return await self._notify_exec_tx_status(req)

    async def done_exec_tx(
        self,
        neon_tx_hash: EthTxHash,
        code: ExecTxDoneCode,
        sender: NeonAccountModel,
    ) -> ExecTxDoneResp:
        req = ExecTxDoneRequest(
            neon_tx_hash=neon_tx_hash,
            code=code,
            state_tx_cnt=sender.state_tx_cnt,
            balance=sender.balance,
        )
        return await self._done_exec_tx(req)

    async def done_complete_stuck_tx(self, neon_tx_hash: EthTxHash, code: ExecTxDoneCode) -> ExecTxDoneStuckResp:
        req = ExecTxDoneStuckRequest(neon_tx_hash=neon_tx_hash, code=code)
        return await self._done_complete_stuck_tx(req)

    async def get_tx_by_hash(self, ctx_id: dict, neon_tx_hash: EthTxHash) -> NeonTxModel:
        req = MpGetTxByHashRequest(ctx_id=ctx_id, neon_tx_hash=neon_tx_hash)
        resp = await self._get_tx_by_hash(req)
        return resp.tx

    async def get_tx_by_sender_nonce(self, ctx_id: dict, sender: NeonAddress, tx_nonce: int) -> NeonTxModel:
        req = MpGetTxBySenderNonceRequest(ctx_id=ctx_id, sender=sender, tx_nonce=tx_nonce)
        resp = await self._get_tx_by_sender_nonce(req)
        return resp.tx

    async def get_tx_status_list_by_sender(self, ctx_id: dict, sender: NeonAccountModel) -> MpTxStatusListResp:
        req = MpGetTxStatusListBySender(
            ctx_id=ctx_id,
            sender=sender.neon_address,
            state_tx_cnt=sender.state_tx_cnt,
            balance=sender.balance,
        )
        return await self._get_tx_list_by_sender(req)

    async def get_content(self, ctx_id: dict, chain_id: int) -> MpTxPoolContentResp:
        return await self._get_content(MpRequest(ctx_id=ctx_id, chain_id=chain_id))

    @AppDataClient.method(name="getGasPrice")
    async def _get_gas_price(self) -> MpGasPriceModel: ...

    @AppDataClient.method(name="sendRawTransaction")
    async def _send_raw_transaction(self, request: MpTxRequest) -> MpTxResp: ...

    @AppDataClient.method(name="notifyExecuteTransactionStatus")
    async def _notify_exec_tx_status(self, request: ExecTxNotifyStatusRequest) -> ExecTxNotifyStatusResp: ...

    @AppDataClient.method(name="doneExecuteTransaction")
    async def _done_exec_tx(self, request: ExecTxDoneRequest) -> ExecTxDoneResp: ...

    @AppDataClient.method(name="doneCompleteStuckTransaction")
    async def _done_complete_stuck_tx(self, request: ExecTxDoneStuckRequest) -> ExecTxDoneStuckResp: ...

    @AppDataClient.method(name="getPendingTransactionByHash")
    async def _get_tx_by_hash(self, request: MpGetTxByHashRequest) -> MpGetTxResp: ...

    @AppDataClient.method(name="getPendingTransactionBySenderNonce")
    async def _get_tx_by_sender_nonce(self, request: MpGetTxBySenderNonceRequest) -> MpGetTxResp: ...

    @AppDataClient.method(name="getPendingTransactionStatusesBySender")
    async def _get_tx_list_by_sender(self, request: MpGetTxStatusListBySender) -> MpTxStatusListResp: ...

    @AppDataClient.method(name="getEvmConfig")
    async def _get_evm_cfg(self) -> EvmConfigModel: ...

    @AppDataClient.method(name="getPendingTransactionCounter")
    async def _get_pending_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp: ...

    @AppDataClient.method(name="getMempoolTransactionCounter")
    async def _get_mempool_tx_cnt(self, request: MpTxCntRequest) -> MpTxCntResp: ...

    @AppDataClient.method(name="getMempoolContent")
    async def _get_content(self, request: MpRequest) -> MpTxPoolContentResp: ...

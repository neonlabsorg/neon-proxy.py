from typing import Sequence, ClassVar

from common.app_data.client import AppDataClient
from common.neon.address import NeonAddress
from common.neon.transaction_model import NeonSkdTxModel
from .ex_api import (
    EXECUTOR_ENDPOINT,
    ExecTxRequest,
    ExecTxResp,
    DestroyAltListRequest,
    DestroyAltListResp,
    NeonAltModel,
    ExecTokenModel,
    CompleteStuckTxRequest,
    CompleteStuckTxResp,
    DestroyTreeAccountResp,
    DestroyTreeAccountRequest,
)
from .mp_api import MpTxModel, MpStuckTxModel


class ExecutorClient(AppDataClient):
    name: ClassVar[str] = "Executor"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(host=self._cfg.exec_ip, port=self._cfg.exec_port, path=EXECUTOR_ENDPOINT)
        self.set_timeout_sec(60 * 90)  # 90 minutes

    async def exec_tx(self, tx: MpTxModel, token: ExecTokenModel) -> ExecTxResp:
        return await self._exec_tx(ExecTxRequest(tx=tx, token=token))

    async def complete_stuck_tx(self, stuck_tx: MpStuckTxModel) -> CompleteStuckTxResp:
        return await self._complete_stuck_tx(CompleteStuckTxRequest(stuck_tx=stuck_tx))

    async def destroy_tree_account(self, skd_tx: NeonSkdTxModel, token: ExecTokenModel) -> DestroyTreeAccountResp:
        request = DestroyTreeAccountRequest(
            neon_tx_hash=skd_tx.neon_tx_hash,
            payer=NeonAddress.from_raw(skd_tx.sol_skd_payer, token.chain_id),
            nonce=skd_tx.nonce,
            token=token,
        )
        return await self._destroy_tree_account(request)

    async def destroy_alt_list(self, req_id: dict, stuck_alt_list: Sequence[NeonAltModel]) -> None:
        req = DestroyAltListRequest(req_id=req_id, alt_list=list(stuck_alt_list))
        await self._destroy_alt_list(req)

    @AppDataClient.method(name="executeNeonTransaction")
    async def _exec_tx(self, request: ExecTxRequest) -> ExecTxResp: ...

    @AppDataClient.method(name="completeStuckNeonTransaction")
    async def _complete_stuck_tx(self, request: CompleteStuckTxRequest) -> CompleteStuckTxResp: ...

    @AppDataClient.method(name="destroyTreeAccount")
    async def _destroy_tree_account(self, request: DestroyTreeAccountRequest) -> DestroyTreeAccountResp: ...

    @AppDataClient.method(name="destroyAltList")
    async def _destroy_alt_list(self, request: DestroyAltListRequest) -> DestroyAltListResp: ...

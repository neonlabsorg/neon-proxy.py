from __future__ import annotations

import logging
from typing import Sequence

from common.cmd_client.cmd_handler import BaseCmdHandler
from common.cu_price.client import SolCuPriceClient
from common.neon_rpc.api_client import CoreApiClient
from common.neon_rpc.transaction_list_sender import SolNeonTxListSender
from common.solana.alt_info import SolAltInfo
from common.solana.cb_program import SolCbCfg, SolCbProg
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from common.solana_rpc.transaction_list_sender_stat import SolTxStatClient, SolTxDoneData, SolTxFailData
from common.utils.cached import cached_method
from proxy.base.mp_client import MempoolClient
from proxy.base.op_client import OpResourceClient
from proxy.executor.transaction_list_signer import OpTxListSigner

_LOG = logging.getLogger(__name__)


class BaseNPCmdHandler(BaseCmdHandler):
    @cached_method
    async def _get_mp_client(self) -> MempoolClient:
        return await self._new_client(MempoolClient, self._cfg)

    @cached_method
    async def _get_op_client(self) -> OpResourceClient:
        return await self._new_client(OpResourceClient, self._cfg)

    @cached_method
    async def _get_cu_price_client(self) -> SolCuPriceClient:
        return await self._new_client(SolCuPriceClient, self._cfg)

    async def _send_tx(
        self,
        req_id: dict,
        payer: SolPubKey,
        ix_list: SolTxIx | Sequence[SolTxIx],
        alt_list: Sequence[SolAltInfo] = tuple(),
    ) -> bool:
        sol_client: SolClient = await self._get_sol_client()
        cu_price_client: SolCuPriceClient = await self._get_cu_price_client()
        op_client: OpResourceClient = await self._get_op_client()
        core_api_client: CoreApiClient = await self._get_core_api_client()

        stat_client = _FakeTxStatClient()
        tx_list_signer = OpTxListSigner(req_id, payer, op_client)

        tx_list_sender = SolNeonTxListSender(
            self._cfg,
            sol_client,
            tx_list_signer,
            stat_client,
            core_api_client,
            cu_price_client,
        )

        cb_cfg = SolCbCfg(heap_size=SolCbProg.MaxHeapSize)

        try:
            return await tx_list_sender.send_tx(ix_list, cb_cfg, alt_list)
        except BaseException as exc:
            _LOG.error("got error %s", str(exc))

        return False


class _FakeTxStatClient(SolTxStatClient):
    def commit_sol_tx_done(self, data: SolTxDoneData) -> None: ...
    def commit_sol_tx_fail(self, data: SolTxFailData) -> None: ...

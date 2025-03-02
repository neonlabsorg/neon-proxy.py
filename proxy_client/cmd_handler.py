from __future__ import annotations

import asyncio
from typing import Sequence

from common.cmd_client.cmd_handler import BaseCmdHandler
from common.neon_rpc.api import EvmConfigModel
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana.transaction import SolTx
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_method
from proxy.base.mp_client import MempoolClient
from proxy.base.op_client import OpResourceClient


class BaseNPCmdHandler(BaseCmdHandler):
    @cached_method
    async def _get_mp_client(self) -> MempoolClient:
        return await self._new_client(MempoolClient, self._cfg)

    @cached_method
    async def _get_op_client(self) -> OpResourceClient:
        return await self._new_client(OpResourceClient, self._cfg)

    async def _send_tx_list(self, req_id: dict, payer: SolPubKey, tx_list: Sequence[SolTx], timeout_sec: int) -> None:
        sol_client: SolClient = await self._get_sol_client()
        op_client: OpResourceClient = await self._get_op_client()
        blockhash, _ = await sol_client.get_recent_blockhash(commit=SolCommit.Finalized)

        for tx in tx_list:
            tx.set_recent_blockhash(blockhash)

        tx_list = await op_client.sign_sol_tx_list(req_id, payer, tx_list)
        await sol_client.send_tx_list(tx_list, skip_preflight=True, max_retry_cnt=None)
        await asyncio.sleep(timeout_sec)

from __future__ import annotations

from typing import ClassVar

from common.jsonrpc.api import BaseJsonRpcModel
from common.utils.pydantic import HexUIntField
from .server_abc import NeonProxyApi


class _RpcSyncingResp(BaseJsonRpcModel):
    startingBlock: HexUIntField
    currentBlock: HexUIntField
    highestBlock: HexUIntField


class NpNetApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::NetStatus"

    @NeonProxyApi.method(name="net_peerCount")
    async def get_net_peer_count(self) -> HexUIntField:
        cluster_node_list = await self._sol_client.get_sol_node_list()
        return len(cluster_node_list)

    @NeonProxyApi.method(name="net_listening")
    def get_net_listening(self) -> bool:
        return False

    @NeonProxyApi.method(name="eth_mining")
    def eth_mining(self) -> bool:
        return False

    @NeonProxyApi.method(name="eth_syncing")
    async def eth_syncing(self) -> bool | _RpcSyncingResp:
        try:
            slot_cnt_behind = await self._sol_client.get_health()
            latest_slot = await self._db.get_latest_slot()
            first_slot = await self._db.get_earliest_slot()

            if ((slot_cnt_behind or None) < 64) or (not latest_slot) or (not first_slot):
                return False

            return _RpcSyncingResp(
                startingBlock=first_slot,
                currentBlock=latest_slot,
                highestBlock=latest_slot + (slot_cnt_behind or 0),
            )

        except (BaseException,):
            return False

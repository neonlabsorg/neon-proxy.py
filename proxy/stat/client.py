from __future__ import annotations

from common.app_data.client import AppDataClient
from common.config.config import Config
from common.solana_rpc.transaction_list_sender_stat import SolTxStatClient, SolTxFailData, SolTxDoneData
from common.stat.api import RpcCallData
from common.stat.client import BaseStatClient
from common.stat.client_rpc import RpcStatClient
from .api import (
    OpEarnedTokenBalanceData,
    OpResourceHolderStatusData,
    OpExecTokenBalanceData,
    STATISTIC_ENDPOINT,
    NeonTxDoneData,
    NeonTxFailData,
    NeonTxPoolData,
)


class StatClient(AppDataClient, BaseStatClient, RpcStatClient, SolTxStatClient):
    def __init__(self, cfg: Config) -> None:
        AppDataClient.__init__(self, cfg)
        BaseStatClient.__init__(self, cfg)
        RpcStatClient.__init__(self)
        self.connect(host=cfg.stat_ip, port=cfg.stat_port, path=STATISTIC_ENDPOINT)

    async def start(self) -> None:
        await AppDataClient.start(self)
        await BaseStatClient.start(self)

    async def stop(self) -> None:
        await AppDataClient.stop(self)
        await BaseStatClient.stop(self)

    def commit_op_earned_tokens_balance(self, data: OpEarnedTokenBalanceData) -> None:
        self._put_to_queue(self._commit_op_earned_tokens_balance, data)

    def commit_op_resource_holder_status(self, data: OpResourceHolderStatusData) -> None:
        self._put_to_queue(self._commit_op_resource_holder_status, data)

    def commit_op_exec_token_balance(self, data: OpExecTokenBalanceData) -> None:
        self._put_to_queue(self._commit_op_exec_token_balance, data)

    def commit_neon_tx_done(self, data: NeonTxDoneData) -> None:
        self._put_to_queue(self._commit_neon_tx_done, data)

    def commit_neon_tx_fail(self, data: NeonTxFailData) -> None:
        self._put_to_queue(self._commit_neon_tx_fail, data)

    def commit_neon_tx_pool(self, data: NeonTxPoolData) -> None:
        self._put_to_queue(self._commit_neon_tx_pool, data)

    def commit_rpc_call(self, data: RpcCallData) -> None:
        self._put_to_queue(self._commit_rpc_call, data)

    def commit_sol_tx_done(self, data: SolTxDoneData) -> None:
        self._put_to_queue(self._commit_sol_tx_done, data)

    def commit_sol_tx_fail(self, data: SolTxFailData) -> None:
        self._put_to_queue(self._commit_sol_tx_fail, data)

    @AppDataClient.method(name="commitOpEarnedTokensBalance")
    async def _commit_op_earned_tokens_balance(self, data: OpEarnedTokenBalanceData) -> None: ...

    @AppDataClient.method(name="commitOpResourceHolderStatus")
    async def _commit_op_resource_holder_status(self, data: OpResourceHolderStatusData) -> None: ...

    @AppDataClient.method(name="commitOpExecutionTokenBalance")
    async def _commit_op_exec_token_balance(self, data: OpExecTokenBalanceData) -> None: ...

    @AppDataClient.method(name="commitRpcCall")
    async def _commit_rpc_call(self, data: RpcCallData) -> None: ...

    @AppDataClient.method(name="commitNeonTransactionDone")
    async def _commit_neon_tx_done(self, data: NeonTxDoneData) -> None: ...

    @AppDataClient.method(name="commitNeonTransactionFail")
    async def _commit_neon_tx_fail(self, data: NeonTxFailData) -> None: ...

    @AppDataClient.method(name="commitNeonTransactionPool")
    async def _commit_neon_tx_pool(self, data: NeonTxPoolData) -> None: ...

    @AppDataClient.method(name="commitSolanaTransactionDone")
    async def _commit_sol_tx_done(self, data: SolTxDoneData) -> None: ...

    @AppDataClient.method(name="commitSolanaTransactionFail")
    async def _commit_sol_tx_fail(self, data: SolTxFailData) -> None: ...

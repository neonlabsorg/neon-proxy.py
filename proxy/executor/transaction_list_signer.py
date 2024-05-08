from typing import Sequence

from common.solana.pubkey import SolPubKey
from common.solana.transaction import SolTx
from common.solana_rpc.transaction_list_sender import SolTxListSigner
from ..base.op_client import OpResourceClient


class OpTxListSigner(SolTxListSigner):
    def __init__(self, tx_id: str, payer: SolPubKey, op_client: OpResourceClient) -> None:
        self._tx_id = tx_id
        self._payer = payer
        self._op_client = op_client

    async def sign_tx_list(self, sol_tx_list: Sequence[SolTx]) -> tuple[SolTx, ...]:
        return await self._op_client.sign_sol_tx_list(self._tx_id, self._payer, sol_tx_list)

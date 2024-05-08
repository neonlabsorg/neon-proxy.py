from typing import Sequence

from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.solana_rpc.transaction_list_sender import SolTxListSigner


class OpTxListSigner(SolTxListSigner):
    def __init__(self, signer: SolSigner) -> None:
        self._signer = signer

    async def sign_tx_list(self, sol_tx_list: Sequence[SolTx]) -> tuple[SolTx, ...]:
        for tx in sol_tx_list:
            tx.sign(self._signer)
        return tuple(sol_tx_list)

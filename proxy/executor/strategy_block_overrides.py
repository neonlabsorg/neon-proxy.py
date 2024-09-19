from typing import ClassVar, Sequence


from .strategy_iterative_holder import HolderTxStrategy
from common.solana.transaction import SolTx
from common.neon.neon_program import NeonEvmIxCode


class BlockOverridesStrategy(HolderTxStrategy):
    name: ClassVar[str] = NeonEvmIxCode.TxStepFromAccount.name + "WithBlockOverrides"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._first_tx_submitted = False


#    async def _prepare_tx_list_for_send(self) -> tuple[SolTx, ...] | None:
#        if not (iter_list_cfg := await self._get_single_iter_list_cfg()):
#            if not (iter_list_cfg := await self._get_iter_list_cfg()):
#                return None
#            tx_list = iter_list_cfg.tx_list
#            if not tx_list:
#                tx_list = tuple(self._build_tx(iter_list_cfg) for _ in range(iter_list_cfg.iter_cnt))
#            if self._first_tx_submitted:
#                return tx_list[:-1]
#            else:
#                return tuple(tx_list[0])
#
#    async def _send_tx_list(self, tx_list: Sequence[SolTx]) -> bool:
#        res: bool = await super()._send_tx_list(tx_list)
#        if res:
#            if not self._first_tx_submitted:
#                self._first_tx_submitted = True
#                res = False
#        return res

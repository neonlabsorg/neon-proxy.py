from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import HolderAccountStatus
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_base import BaseTxPrepStage


class WriteHolderTxPrepStage(BaseTxPrepStage):
    name = NeonEvmIxCode.HolderWrite.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_status = HolderAccountStatus.Empty

    def get_tx_name_list(self) -> tuple[str, ...]:
        if self._ctx.is_stuck_tx:
            return tuple()
        return tuple([self.name])

    async def build_tx_list(self) -> list[list[SolTx]]:
        if self._ctx.is_stuck_tx or self._ctx.has_sol_tx(self.name):
            return list()

        cu_price = self._cu_price
        cb_prog = self._ctx.cb_prog
        neon_prog = self._ctx.neon_prog

        tx_list: list[SolTx] = list()
        holder_msg_offset = 0
        holder_msg = neon_prog.holder_msg

        holder_msg_size = 900
        while len(holder_msg):
            holder_msg_part, holder_msg = holder_msg[:holder_msg_size], holder_msg[holder_msg_size:]

            ix_list = list()
            if cu_price:
                ix_list.append(cb_prog.make_cu_price_ix(cu_price))
            ix_list.append(cb_prog.make_cu_limit_ix(10_000))
            ix_list.append(neon_prog.make_write_ix(holder_msg_offset, holder_msg_part))

            tx_list.append(SolLegacyTx(name=self.name, ix_list=ix_list))
            holder_msg_offset += holder_msg_size

        return [tx_list]

    async def update_after_emulate(self) -> None:
        pass

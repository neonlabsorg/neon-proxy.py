import logging

from common.neon.neon_program import NeonEvmIxCode
from common.neon_rpc.api import HolderAccountStatus, HolderAccountModel
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from .errors import BadResourceError, StuckTxError
from .strategy_base import BaseTxPrepStage

_LOG = logging.getLogger(__name__)


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
            ix_list.append(neon_prog.make_write_ix(holder_msg_offset, holder_msg_part))

            tx_list.append(SolLegacyTx(name=self.name, ix_list=ix_list))
            holder_msg_offset += holder_msg_size

        return [tx_list]

    async def update_after_emulate(self) -> None:
        if self._ctx.is_stuck_tx:
            return

        holder = await self._get_holder_account()
        if holder.status == HolderAccountStatus.Active:
            if holder.neon_tx_hash != self._ctx.neon_tx_hash:
                raise StuckTxError(holder.neon_tx_hash, holder.address)

    async def _get_holder_account(self) -> HolderAccountModel:
        holder = await self._ctx.core_api_client.get_holder_account(self._ctx.holder_address)
        if holder.status not in (HolderAccountStatus.Finalized, HolderAccountStatus.Active, HolderAccountStatus.Holder):
            raise BadResourceError(f"Holder account {holder.address} has bad tag: {holder.status}")
        return holder

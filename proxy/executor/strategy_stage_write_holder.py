import logging
from typing import ClassVar

from common.neon.neon_program import NeonEvmIxCode, NeonIxMode
from common.neon_rpc.api import HolderAccountStatus
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from .strategy_base import BaseTxPrepStage


_LOG = logging.getLogger(__name__)


class WriteHolderTxPrepStage(BaseTxPrepStage):
    name: ClassVar[str] = NeonEvmIxCode.HolderWrite.name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_status = HolderAccountStatus.Empty

    def get_tx_name_list(self) -> tuple[str, ...]:
        if self._ctx.is_stuck_tx:
            return tuple()
        return tuple([self.name, "StepFromAccFirstIteration"])

    async def build_tx_list(self) -> list[list[SolTx]]:
        if self._ctx.is_stuck_tx or self._ctx.has_sol_tx(self.name):
            return list()

        cu_price = self._cu_price
        cb_prog = self._ctx.cb_prog
        neon_prog = self._ctx.neon_prog

        holder_tx_list: list[SolTx] = list()
        ret_tx_list: list[list[SolTx]] = [holder_tx_list]
        holder_msg_offset = 0
        holder_msg = neon_prog.holder_msg

        holder_msg_size = 930
        while len(holder_msg):
            holder_msg_part, holder_msg = holder_msg[:holder_msg_size], holder_msg[holder_msg_size:]

            ix_list = list()
            if cu_price:
                ix_list.append(cb_prog.make_cu_price_ix(cu_price))
            ix_list.append(cb_prog.make_cu_limit_ix(7_500))
            ix_list.append(neon_prog.make_write_ix(holder_msg_offset, holder_msg_part))

            holder_tx_list.append(SolLegacyTx(name=self.name, ix_list=ix_list))
            holder_msg_offset += holder_msg_size

        # If the block timestamp or block number is used (and we know it from the first emulation):
        # - First iteration writes block timestamp/number into the holder and fixes it.
        # - Re-emulation before the execution gets the correct account list based on the
        #   block timestamp and block number written to the holder by the first iteration.
        # - Subsequent iterations have the correct account list.
        if self._ctx.is_timestamp_number_used:
            first_step_ix_list = list()
            if cu_price:
                first_step_ix_list.append(cb_prog.make_cu_price_ix(cu_price))
            # TODO: change the limit.
            first_step_ix_list.append(cb_prog.make_cu_limit_ix(1_350_500))
            first_step_ix_list.append(
                neon_prog.make_tx_step_from_account_ix(
                    NeonIxMode.FullWritable, self._ctx.evm_step_cnt_per_iter, self._ctx.next_uniq_idx()
                )
            )
            ret_tx_list.append([SolLegacyTx(name="StepFromAccFirstIteration", ix_list=first_step_ix_list)])

        return ret_tx_list

    async def update_after_emulate(self) -> None:
        pass

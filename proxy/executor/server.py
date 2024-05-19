import asyncio

from .alt_destroyer import SolAltDestroyer
from .ex_stuck_alt_api import SolAltApi
from .ex_transaction_api import NeonTxExecApi
from .server_abc import ExecutorServerAbc
from .transaction_executor import NeonTxExecutor


class ExecutorServer(ExecutorServerAbc):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.listen(host="127.0.0.1", port=self._cfg.exec_port)
        self._process_pool.set_process_cnt(self._cfg.mp_exec_process_cnt)

        self._neon_tx_executor = NeonTxExecutor(self)
        self._sol_alt_destroyer = SolAltDestroyer(self)

        self._add_api(NeonTxExecApi(self))
        self._add_api(SolAltApi(self))

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._sol_alt_destroyer.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            super()._on_server_stop(),
            self._sol_alt_destroyer.stop(),
        )

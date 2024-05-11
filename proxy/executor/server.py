import os

from .ex_transaction_api import NeonTxExecApi
from .server_abc import ExecutorServerAbc
from .transaction_executor import NeonTxExecutor


class ExecutorServer(ExecutorServerAbc):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.set_process_cnt(os.cpu_count())
        self.set_worker_cnt(1)
        self.listen(host="127.0.0.1", port=self._cfg.executor_port)

        self._neon_tx_executor = NeonTxExecutor(self)

        self._add_api(NeonTxExecApi(self))

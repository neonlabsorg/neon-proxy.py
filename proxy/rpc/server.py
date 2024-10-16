from __future__ import annotations

import logging
from typing import ClassVar

from .np_account_api import NpAccountApi
from .np_block_transaction_api import NpBlockTxApi
from .np_call_api import NpCallApi
from .np_gas_price import NpGasPriceApi
from .np_net_api import NpNetApi
from .np_send_transaction_api import NpExecTxApi
from .np_transaction_logs_api import NpTxLogsApi
from .np_version_api import NpVersionApi
from .server_abc import NeonProxyAbc

_ENDPOINT_LIST = ["/solana", "/solana/:token", "/", "/:token"]
_LOG = logging.getLogger(__name__)


class NeonProxy(NeonProxyAbc):
    _stat_name: ClassVar[str] = "PublicRpc"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.listen(host="0.0.0.0", port=self._cfg.rpc_public_port)
        self.set_worker_cnt(self._cfg.rpc_worker_cnt)
        self._process_pool.set_process_cnt(self._cfg.rpc_process_cnt)

        self._add_api(NpVersionApi(self))
        self._add_api(NpBlockTxApi(self))
        self._add_api(NpGasPriceApi(self))
        self._add_api(NpCallApi(self))
        self._add_api(NpAccountApi(self))
        self._add_api(NpTxLogsApi(self))
        self._add_api(NpNetApi(self))

        if self._cfg.enable_send_tx_api:
            self._add_api(NpExecTxApi(self))

    @classmethod
    def _get_endpoint_list(cls) -> list[str]:
        return _ENDPOINT_LIST

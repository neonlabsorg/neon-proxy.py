from typing import ClassVar

from .pr_eth_account_api import PrEthAccountApi
from .pr_eth_tx_api import PrEthTxApi
from .pr_mempool_api import PrMempoolApi
from .server_abc import PrivateRpcServerAbc

_ENDPOINT_LIST = ["/", "/:token"]


class PrivateRpcServer(PrivateRpcServerAbc):
    _stat_name: ClassVar[str] = "PrivateRpc"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.listen(host=self._cfg.rpc_private_ip, port=self._cfg.rpc_private_port)

        self._add_api(PrEthAccountApi(self))
        self._add_api(PrEthTxApi(self))
        self._add_api(PrMempoolApi(self))

    @classmethod
    def _get_endpoint_list(cls) -> list[str]:
        return _ENDPOINT_LIST

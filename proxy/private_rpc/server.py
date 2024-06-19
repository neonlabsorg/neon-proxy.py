from .pr_eth_account_api import PrEthAccountApi
from .pr_eth_sign_api import PrEthSignApi
from .pr_eth_tx_api import PrEthTxApi
from .pr_mempool_api import PrMempoolApi
from .server_abc import PrivateRpcServerAbc


class PrivateRpcServer(PrivateRpcServerAbc):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.listen(host=self._cfg.rpc_private_ip, port=self._cfg.rpc_private_port)

        self._add_api(PrEthAccountApi(self))
        self._add_api(PrEthSignApi(self))
        self._add_api(PrEthTxApi(self))
        self._add_api(PrMempoolApi(self))

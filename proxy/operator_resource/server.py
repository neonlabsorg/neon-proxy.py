import asyncio

from common.solana.signer import SolSigner
from .op_acquire_resource_api import OpAcquireResourceApi
from .op_balance_api import OpBalanceApi
from .op_eth_sign_api import OpEthSignApi
from .op_sol_sign_api import OpSolSignApi
from .resource_manager import OpResourceMng
from .secret_manager import OpSecretMng
from .server_abc import OpResourceServerAbc


class OpResourceServer(OpResourceServerAbc):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.listen(host=self._cfg.op_resource_ip, port=self._cfg.op_resource_port)

        self._op_secret_mng = OpSecretMng(self)
        self._op_resource_mng = OpResourceMng(self)

        self._add_api(OpAcquireResourceApi(self))
        self._add_api(OpEthSignApi(self))
        self._add_api(OpSolSignApi(self))
        self._add_api(OpBalanceApi(self))

    async def get_signer_list(self) -> tuple[SolSigner, ...]:
        return await self._op_secret_mng.get_signer_list()

    async def _on_server_start(self) -> None:
        await asyncio.gather(
            super()._on_server_start(),
            self._op_secret_mng.start(),
            self._op_resource_mng.start(),
        )

    async def _on_server_stop(self) -> None:
        await asyncio.gather(
            super()._on_server_stop(),
            self._op_secret_mng.stop(),
            self._op_resource_mng.stop(),
        )

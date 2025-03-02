import asyncio
import logging

from common.config.constants import ONE_BLOCK_SEC
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel
from common.solana_rpc.ws_client import SolWatchAccountSession
from common.utils.json_logger import logging_context
from .server_abc import MempoolComponent, MempoolServerAbc

_LOG = logging.getLogger(__name__)


class MpEvmConfigReader(MempoolComponent):
    def __init__(self, server: MempoolServerAbc) -> None:
        super().__init__(server)
        self._watch_session = SolWatchAccountSession(self._cfg, self._sol_client, init_account=False)
        self._evm_cfg_cache = EvmConfigModel.default()
        self._update_evm_cfg_task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        await self._watch_session.subscribe_account(NeonProg.ID)
        await self._update_evm_cfg()
        self._watch_session.pop_changed_key_list()
        self._update_evm_cfg_task = asyncio.create_task(self._update_evm_cfg_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if task := self._update_evm_cfg_task:
            self._update_evm_cfg_task = None
            await task

        if watch_session := self._watch_session:
            self._watch_session = None
            await watch_session.safe_disconnect()

    def get_evm_cfg(self) -> EvmConfigModel:
        return self._evm_cfg_cache

    async def _update_evm_cfg_loop(self) -> None:
        stop_task = asyncio.create_task(self._stop_event.wait())
        while not self._stop_event.is_set():
            with logging_context(ctx="mp-evm-cfg"):
                try:
                    await self._watch_session.update()
                    if self._watch_session.pop_changed_key_list():
                        await self._update_evm_cfg()
                except BaseException as exc:
                    _LOG.error("error on update evm-config", exc_info=exc)

            await asyncio.wait({stop_task}, timeout=ONE_BLOCK_SEC)

    async def _update_evm_cfg(self) -> None:
        if not (evm_cfg := await self._core_api_client.get_evm_cfg()):
            return

        self._evm_cfg_cache = evm_cfg
        neon_prog_cfg = evm_cfg.neon_prog_cfg
        NeonProg.init_prog(neon_prog_cfg)

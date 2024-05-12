from __future__ import annotations

import logging
from typing import Any

from .log_level import get_core_api_log_level
from .api import CoreApiResp, EvmConfigModel, HolderAccountModel, NeonAccountModel
from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..neon.account import NeonAccount
from ..neon.neon_program import NeonProg
from ..solana.pubkey import SolPubKey
from ..utils.async_cmd_client import AsyncCmdClient, AsyncStreamType, AsyncStreamReader, ProcessError
from ..utils.cached import cached_method

_LOG = logging.getLogger(__name__)


class NeonCmdClient(AsyncCmdClient):
    def __init__(self, cfg: Config):
        super().__init__("neon-cli", cfg.debug_cmd_line)
        self._cfg = cfg
        self._log_level = get_core_api_log_level()
        self._msg_filter = LogMsgFilter(self._cfg)

    async def _run_cmd_client(self, arg_list: list[str]) -> dict[str, Any] | list:
        sol_url = self._cfg.random_sol_url
        # fmt: off
        arg_list = [
            "--commitment", "recent",
            "--url", sol_url,
            "--evm_loader", NeonProg.ID.to_string(),
            "--loglevel", self._log_level,
        ] + arg_list
        # fmt: on
        process = await super()._run_cmd_client(arg_list)
        resp = CoreApiResp.model_validate_json(process.stdout)
        if resp.error:
            error_str = resp.error
            _LOG.error("error on calling %s: %s", self._prog, error_str, extra=self._msg_filter)
            raise ProcessError(process, resp.error)
        return resp.value

    async def _read_stream(self, stream_type: AsyncStreamType, stream: AsyncStreamReader) -> str:
        if stream_type == AsyncStreamType.StdOut:
            return await self._read_full_stream(stream_type, stream)
        return await super()._read_stream(stream_type, stream)

    @cached_method
    async def get_version(self) -> str:
        process = await super()._run_cmd_client(["--version"])
        return process.stdout.split()[1]

    async def get_neon_account_model(self, neon_account: NeonAccount) -> NeonAccountModel:
        json_data_list = await self._run_cmd_client(
            [
                "get-ether-account-data",
                neon_account.to_address(),
                neon_account.chain_id,
            ]
        )
        json_data = json_data_list[0]
        return NeonAccountModel.from_dict(json_data, account=neon_account)

    async def get_holder_account_model(self, address: SolPubKey) -> HolderAccountModel:
        json_acct = await self._run_cmd_client(["get-holder-account-data", address.to_string()])
        return HolderAccountModel.from_dict(address, json_acct)

    async def get_evm_cfg(self) -> EvmConfigModel:
        _LOG.debug("read EVM config")
        json_cfg = await self._run_cmd_client(["neon-elf-params"])
        return EvmConfigModel.from_dict(json_cfg, deployed_slot=0)

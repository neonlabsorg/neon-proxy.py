from __future__ import annotations

import itertools
import logging
import os

import hvac
from hvac.api.secrets_engines.kv_v2 import DEFAULT_MOUNT_POINT

from common.solana.signer import SolSigner
from common.solana_rpc.cmd_client import SolCmdClient
from .server_abc import OpResourceComponent

_LOG = logging.getLogger(__name__)


class OpSecretMng(OpResourceComponent):
    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def get_signer_list(self) -> tuple[SolSigner, ...]:
        if self._cfg.hvac_url is not None:
            secret_list = await self._read_secret_list_from_hvac()
        else:
            secret_list = await self._read_secret_list_from_fs()

        if not secret_list:
            _LOG.warning("no signer")
        else:
            _LOG.debug("got signer list of: %s - keys", len(secret_list))
        return secret_list

    async def _read_secret_list_from_hvac(self) -> tuple[SolSigner, ...]:
        _LOG.debug("read secret keys from HashiCorp Vault...")

        client = hvac.Client(url=self._cfg.hvac_url, token=self._cfg.hvac_token)
        if not client.is_authenticated():
            _LOG.error("cannot connect to HashiCorp Vault!")
            return tuple()

        mount = self._cfg.hvac_mount if self._cfg.hvac_mount is not None else DEFAULT_MOUNT_POINT
        base_path = self._cfg.hvac_path
        try:
            response_list = client.secrets.kv.v2.list_secrets(path=base_path, mount_point=mount)
        except (BaseException,):
            _LOG.error("fail to read secret list from %s", base_path)
            return tuple()

        secret_list: list[SolSigner] = list()
        for key_name in response_list.get("data", dict()).get("keys", list()):
            key_path = os.path.join(base_path, key_name)
            try:
                data = client.secrets.kv.v2.read_secret(path=key_path, mount_point=mount)
                secret: str = data.get("data", dict()).get("data", dict()).get("secret_key", None)
                if not secret:
                    _LOG.error("no secret_key in the path %s", key_path)
                    continue

                sol_account = SolSigner.from_raw(secret)
                secret_list.append(sol_account)
                _LOG.debug("got secret for %s", sol_account.pubkey)

            except (BaseException,):
                _LOG.error("error on read secret from %s", key_path)

        return tuple(secret_list)

    async def _read_secret_list_from_fs(self) -> tuple[SolSigner, ...]:
        _LOG.debug("read secret keys from filesystem...")

        keypair_file = await SolCmdClient(self._cfg).get_keypair_file()
        if not keypair_file:
            _LOG.warning("no keypair path")
            return tuple()

        secret_list: list[SolSigner] = list()
        file_name, file_ext = os.path.splitext(keypair_file.strip())
        for idx in itertools.count(1):
            full_path = file_name + (str(idx) if idx > 1 else "") + file_ext
            if not os.path.isfile(full_path):
                break

            sol_account = self._read_secret_file(full_path)
            if not sol_account:
                continue
            secret_list.append(sol_account)
            _LOG.debug("got secret for %s", sol_account.pubkey)

        return tuple(secret_list)

    @staticmethod
    def _read_secret_file(file_name: str) -> SolSigner | None:
        try:
            _LOG.debug("open a secret file: %s", file_name)
            with open(file_name.strip(), mode="r") as src:
                line = src.read()
                raw_key = [int(v) for v in line.strip("[] \n").split(",") if 0 <= int(v) <= 255]
                if len(raw_key) < 32:
                    _LOG.debug("wrong content in the file %s", file_name)
                    return None
                return SolSigner.from_raw(raw_key)
        except (BaseException,):
            _LOG.warning("error on read secret from %s", file_name)
            return None

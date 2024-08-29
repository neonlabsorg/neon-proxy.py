from __future__ import annotations

import itertools
import logging
import os
import re
import subprocess
import time
import multiprocessing as mp
from typing import Any, Final

from .log_level import get_core_api_log_level
from ..config.config import Config
from ..config.utils import LogMsgFilter
from ..neon.neon_program import NeonProg
from ..utils.json_logger import log_msg

_LOG = logging.getLogger(__name__)


class _Server:
    # skip date-time
    _skip_len: Final[int] = len("2024-02-20T21:59:26.318980Z ")
    # 7-bit C1 ANSI sequences
    _ansi_escape: Final[re.Pattern] = re.compile(
        r"""
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by a control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    """,
        re.VERBOSE,
    )

    def __init__(self, cfg: Config, idx: int, solana_url: str):
        self._cfg = cfg
        self._msg_filter = LogMsgFilter(cfg)
        port = cfg.neon_core_api_port + idx
        self._host = f"{cfg.neon_core_api_ip}:{port}"
        self._solana_url = solana_url
        self._process: mp.Process | None = None
        self._stop_event = mp.Event()

    def start(self) -> None:
        self._process = process = mp.Process(target=self._run)
        process.start()

    def stop(self) -> None:
        self._stop_event.set()
        time.sleep(0.1)

        self._process.kill()
        self._process.join()

    def _create_env(self) -> dict[str, Any]:
        log_level = get_core_api_log_level()

        new_env = dict(
            RUST_LOG=log_level,
            SOLANA_URL=self._solana_url,
            NEON_API_LISTENER_ADDR=self._host,
            COMMITMENT="recent",
            EVM_LOADER=str(NeonProg.ID),
            NEON_DB_CLICKHOUSE_URLS=";".join(self._cfg.ch_dsn_list),
            TRACER_DB_TYPE="clickhouse" if len(self._cfg.ch_dsn_list) > 0 else "none",
            SOLANA_KEY_FOR_CONFIG=self._cfg.sol_key_for_evm_cfg.to_string(),
            SOLANA_TEST_ACCOUNTS_INDEX_MEMORY_LIMIT_MB="value",  # This needs to be set in order to disable disk
            # storage for AccountsDb when running Solana Bank Emulator
            SOLANA_RAYON_THREADS="1",
        )

        env = dict(os.environ)
        env.update(new_env)

        return env

    def _run(self):
        cmd = ["neon-core-api", "-H", self._host]
        env = self._create_env()

        while not self._stop_event.is_set():
            self._run_host_api(cmd, env)
            time.sleep(1)

    def _run_host_api(self, cmd_line: list[str], env: dict[str, Any]):
        try:
            _LOG.info(log_msg("start Neon Core API service at the {Host}", Host=self._host))
            process = subprocess.Popen(
                cmd_line,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                env=env,
            )
            while not self._stop_event.is_set():
                line = process.stdout.readline()
                if line:
                    if not self._cfg.debug_cmd_line:
                        continue

                    line = self._ansi_escape.sub("", line).replace('"', "'")
                    pos = line.find(" ", self._skip_len) + 1
                    line = line[pos:-1]
                    _LOG.debug("%s", line.rstrip(), extra=self._msg_filter)
                elif process.poll() is not None:
                    break

        except BaseException as exc:
            _LOG.error(log_msg("unexpected error in Neon Core API: {Error}", Error=str(exc)), extra=self._msg_filter)


class CoreApiServer:
    def __init__(self, cfg: Config) -> None:
        self._instance_list: list[_Server] = list()

        idx = itertools.count()
        for _ in range(cfg.neon_core_api_server_cnt):
            for url in cfg.sol_url_list:
                self._instance_list.append(_Server(cfg, next(idx), url))

    def start(self) -> None:
        for instance in self._instance_list:
            instance.start()

    def stop(self) -> None:
        for instance in self._instance_list:
            instance.stop()

from __future__ import annotations

import logging
import os
import random
import re
from decimal import Decimal
from typing import Final, Union
from urllib.parse import urlparse

from pythclient.solana import (
    PYTHNET_HTTP_ENDPOINT,
    PYTHNET_WS_ENDPOINT,
    SOLANA_DEVNET_HTTP_ENDPOINT,
    SOLANA_MAINNET_HTTP_ENDPOINT,
    SOLANA_MAINNET_WS_ENDPOINT,
    SOLANA_DEVNET_WS_ENDPOINT,
)
from strenum import StrEnum

from .constants import (
    NEON_EVM_PROGRAM_ID,
    ONE_BLOCK_SEC,
    MIN_FINALIZE_SEC,
    DEFAULT_TOKEN_NAME,
    SOL_PACKET_SIZE,
    CHAIN_TOKEN_NAME,
)
from ..solana.commit_level import SolCommit
from ..solana.pubkey import SolPubKey
from ..solana.cb_program import SolCbProg
from ..utils.cached import cached_property, cached_method
from ..utils.format import str_fmt_object

_LOG = logging.getLogger(__name__)
_RE_SPLIT_REGEX = re.compile(r",|;|\s")


class StartSlot:
    class SlotEnum(StrEnum):
        Continue = "continue"
        Latest = "latest"
        Disable = "disable"

    Continue: Final[SlotEnum] = SlotEnum.Continue
    Latest: Final[SlotEnum] = SlotEnum.Latest
    Disable: Final[SlotEnum] = SlotEnum.Disable

    Type = Union[SlotEnum, int]

    @classmethod
    def from_raw(cls, raw: str | int) -> Type:
        if isinstance(raw, int):
            return raw
        elif isinstance(raw, str):
            value = raw.lower().strip()
            try:
                return cls.SlotEnum(value)
            except ValueError:
                pass

            # try to convert to decimal int
            try:
                return int(value, 10)
            except ValueError:
                pass

        raise ValueError(f"Wrong start slot value: {raw}")


def _parse_sol_ws_url(sol_url: str) -> str:
    parsed_sol_url = urlparse(sol_url)
    scheme = "wss" if parsed_sol_url.scheme == "https" else "ws"

    if parsed_sol_url.port is not None:
        port = parsed_sol_url.port + 1
        netloc = f"{parsed_sol_url.hostname}:{port}"
    else:
        netloc = parsed_sol_url.netloc

    parsed_sol_ws_url = parsed_sol_url._replace(scheme=scheme, netloc=netloc)

    return parsed_sol_ws_url.geturl()


class Config:
    hide_sensitive_info_name: Final[str] = "HIDE_SENSITIVE_INFO"
    sol_url_name: Final[str] = "SOLANA_URL"
    sol_ws_url_name: Final[str] = "SOLANA_WS_URL"
    sol_timeout_sec_name: Final[str] = "SOLANA_TIMEOUT"
    enable_private_api_name: Final[str] = "ENABLE_PRIVATE_API"
    enable_send_tx_api_name: Final[str] = "ENABLE_SEND_TX_API"
    max_emulate_evm_step_cnt_name: Final[str] = "MAX_EMULATE_EVM_STEP_COUNT"
    debug_cmd_line_name: Final[str] = "DEBUG_CMD_LINE"
    # Statistic configuration
    gather_stat_name: Final[str] = "GATHER_STATISTICS"
    # Proxy configuration
    rpc_private_ip_name: Final[str] = "RPC_PRIVATE_IP"
    rpc_private_port_name: Final[str] = "RPC_PRIVATE_PORT"
    rpc_public_port_name: Final[str] = "RPC_PUBLIC_PORT"
    rpc_process_cnt_name: Final[str] = "RPC_PROCESS_COUNT"
    rpc_worker_cnt_name: Final[str] = "RPC_WORKER_COUNT"
    # Neon Core API configuration
    neon_core_api_server_cnt_name: Final[str] = "NEON_CORE_API_SERVER_COUNT"
    sol_key_for_evm_cfg_name: Final[str] = "SOLANA_KEY_FOR_EVM_CONFIG"
    # Postgres DB settings
    pg_host_name: Final[str] = "POSTGRES_HOST"
    pg_db_name: Final[str] = "POSTGRES_DB"
    pg_user_name: Final[str] = "POSTGRES_USER"
    pg_password_name: Final[str] = "POSTGRES_PASSWORD"
    pg_timeout_sec_name: Final[str] = "POSTGRES_TIMEOUT"
    pg_conn_cnt_name: Final[str] = "POSTGRES_CONNECTION_COUNT"
    # Base service settings
    base_service_ip_name = "BASE_SERVICE_IP"
    base_service_port_name = "BASE_SERVICE_PORT"
    # Mempool settings
    mp_capacity_name: Final[str] = "MEMPOOL_CAPACITY"
    mp_capacity_high_watermark_name: Final[str] = "MEMPOOL_CAPACITY_HIGH_WATERMARK"
    mp_eviction_timeout_sec_name: Final[str] = "MEMPOOL_EVICTION_TIMEOUT_SEC"
    mp_gas_price_min_window_name: Final[str] = "MEMPOOL_GAS_PRICE_MINUTE_WINDOW"
    mp_cache_life_sec_name: Final[str] = "MEMPOOL_CACHE_LIFE_SEC"
    mp_exec_process_cnt_name: Final[str] = "MEMPOOL_EXECUTOR_PROCESS_COUNT"
    mp_exec_worker_cnt_name: Final[str] = "MEMPOOL_EXECUTOR_WORKER_COUNT"
    mp_skip_stuck_tx_name: Final[str] = "MEMPOOL_SKIP_STUCK_TRANSACTIONS"
    mp_lost_alt_timeout_sec_name: Final[str] = "MEMPOOL_LOST_ALT_TIMEOUT_SEC"
    # Transaction execution settings
    retry_on_fail_name: Final[str] = "RETRY_ON_FAIL"
    commit_timeout_sec_name: Final[str] = "COMMIT_TIMEOUT_SEC"
    commit_level_name: Final[str] = "COMMIT_LEVEL"
    max_tx_account_cnt_name: Final[str] = "MAX_TX_ACCOUNT_COUNT"
    # Gas price settings
    pyth_url_name: Final[str] = "PYTH_URL"
    pyth_ws_url_name: Final[str] = "PYTH_WS_URL"
    operator_fee_name: Final[str] = "OPERATOR_FEE"
    cu_limit_name: Final[str] = "CU_LIMIT"
    cu_price_name: Final[str] = "CU_PRIORITY_FEE"
    simple_cu_price_name: Final[str] = "SIMPLE_CU_PRIORITY_FEE"
    max_cu_price_mult_name: Final[str] = "MAXIMUM_CU_PRIORITY_FEE_MULTIPLIER"
    min_gas_price_name: Final[str] = "MINIMAL_GAS_PRICE"
    min_wo_chain_id_gas_price_name: Final[str] = "MINIMAL_WITHOUT_CHAIN_ID_GAS_PRICE"
    const_gas_price_name: Final[str] = "CONST_GAS_PRICE"
    # Operator resources
    holder_size_name: Final[str] = "HOLDER_SIZE"
    min_op_balance_to_warn_name: Final[str] = "MIN_OPERATOR_BALANCE_TO_WARN"
    min_op_balance_to_err_name: Final[str] = "MIN_OPERATOR_BALANCE_TO_ERR"
    perm_account_id_name: Final[str] = "PERM_ACCOUNT_ID"
    perm_account_limit_name: Final[str] = "PERM_ACCOUNT_LIMIT"
    # HashiCorp Vault settings
    hvac_url_name: Final[str] = "HVAC_URL"
    hvac_token_name: Final[str] = "HVAC_TOKEN"
    hvac_path_name: Final[str] = "HVAC_PATH"
    hvac_mount_name: Final[str] = "HVAC_MOUNT"
    # Indexing settings
    start_slot_name: Final[str] = "START_SLOT"
    indexer_poll_block_cnt_name: Final[str] = "INDEXER_POLL_BLOCK_COUNT"
    indexer_check_msec_name: Final[str] = "INDEXER_CHECK_MSEC"
    stuck_object_blockout_name: Final[str] = "STUCK_OBJECT_BLOCKOUT"
    stuck_object_validate_blockout_name: Final[str] = "STUCK_OBJECT_VALIDATE_BLOCKOUT"
    alt_freeing_depth_name: Final[str] = "ALT_FREEING_DEPTH"
    metrics_log_skip_cnt_name: Final[str] = "METRICS_LOG_SKIP_COUNT"
    op_key_list_name: Final[str] = "OPERATOR_ACCOUNT_LIST"
    # Integration Indexer with Tracer API
    slot_processing_delay_name: Final[str] = "SLOT_PROCESSING_DELAY"
    clickhouse_dsn_list_name: Final[str] = "CLICKHOUSE_DSN_LIST"
    # Reindexing settings
    reindex_start_slot_name: Final[str] = "REINDEX_START_SLOT"
    reindex_thread_cnt_name: Final[str] = "REINDEX_THREAD_COUNT"
    reindex_block_cnt_in_range_name: Final[str] = "REINDEX_BLOCK_COUNT_IN_RANGE"
    reindex_max_range_cnt_name: Final[str] = "REINDEX_MAX_RANGE_COUNT"
    # # Gas-less transaction configuration
    # gas_tank_parallel_request_cnt_name: Final[str] = "GAS_TANK_PARALLEL_REQUEST_COUNT"
    # gas_tank_poll_tx_count_name: Final[str] = "GAS_TANK_POLL_TX_COUNT"
    # gas_less_max_tx_nonce_name: Final[str] = "GAS_LESS_MAX_TX_NONCE"
    # gas_less_max_gas_name: Final[str] = "GAS_LESS_MAX_GAS"
    # Testing settings
    fuzz_fail_pct_name: Final[str] = "FUZZ_FAIL_PCT"

    _pg_null_value: Final[object] = object()
    _1min: Final[int] = 60
    _1hour: Final[int] = 60 * 60
    _1day: Final[int] = 24 * _1hour

    def validate_db_config(self) -> None:
        value_dict = {
            self.pg_host_name: self.pg_host,
            self.pg_db_name: self.pg_db,
            self.pg_user_name: self.pg_user,
            self.pg_password_name: self.pg_password,
        }

        for key, value in value_dict.items():
            if value is self._pg_null_value:
                raise ValueError(f"{key} is not specified")

    @staticmethod
    def _validate_sol_acct(name: str, value: str) -> SolPubKey:
        try:
            return SolPubKey.from_raw(value)
        except ValueError:
            _LOG.warning("%s contains bad Solana account %s", name, value)
            return SolPubKey.default()

    def _env_sol_acct(self, name: str) -> SolPubKey:
        value = os.environ.get(name, None)
        if not value:
            return SolPubKey.default()

        return self._validate_sol_acct(name, value)

    def _env_sol_acct_set(self, name: str) -> set[SolPubKey]:
        raw_acct_list_str = os.environ.get(name, None)
        if not raw_acct_list_str:
            return set()

        sol_acct_set: set[SolPubKey] = set()
        try:
            raw_acct_list = self._split_str(raw_acct_list_str)
        except (BaseException,):
            _LOG.warning("%s contains bad value", name)
            return sol_acct_set

        for raw_acct in raw_acct_list:
            sol_acct = self._validate_sol_acct(name, raw_acct)
            if sol_acct is None:
                continue

            sol_acct_set.add(sol_acct)

        return sol_acct_set

    def _env_dsn_list(self, name: str) -> list[str]:
        raw_dsn_list_str = os.environ.get(name, None)
        if raw_dsn_list_str is None:
            return list()

        dsn_list: list[str] = list()
        try:
            dsn_list = self._split_str(raw_dsn_list_str)
        except (BaseException,):
            _LOG.warning("%s contains bad value", name)

        return dsn_list

    @staticmethod
    def _split_str(src: str) -> list[str]:
        str_list = _RE_SPLIT_REGEX.split(src)
        str_list = [s.strip() for s in str_list]
        return [s for s in str_list if s]

    @staticmethod
    def _env_start_slot(name: str, default_value: StartSlot.Type) -> StartSlot.Type:
        value = os.environ.get(name, None)
        if value is None:
            return default_value

        try:
            return StartSlot.from_raw(value)
        except ValueError:
            _LOG.warning("%s has bad value %s, force to use the default value %s", name, value, default_value)
            return default_value

    @staticmethod
    def _env_bool(name: str, default_value: bool) -> bool:
        true_value_list = ("TRUE", "YES", "ON", "1")
        false_value_list = ("FALSE", "NO", "OFF", "0")
        os_def_value = true_value_list[0] if default_value else false_value_list[0]

        value = os.environ.get(name, os_def_value).upper().strip()  # fmt: skip
        if (value not in true_value_list) and (value not in false_value_list):
            _LOG.warning(
                "%s can be: %s or %s, force to use the default value %s",
                name,
                true_value_list,
                false_value_list,
                os_def_value,
            )
            return default_value

        return value in true_value_list

    @staticmethod
    def _env_num(
        name: str,
        default_value: int | float | Decimal,
        min_value: int | float | Decimal | None = None,
        max_value: int | float | Decimal | None = None,
    ) -> int | float | Decimal:
        value = os.environ.get(name, None)
        if value is None:
            return default_value

        try:
            if isinstance(default_value, int):
                value = int(value, base=10)
            elif isinstance(default_value, float):
                value = float(value)
            else:
                value = Decimal(value)

            if min_value is not None:
                assert type(min_value) is type(default_value), f"{type(min_value)} is {type(default_value)}"
                if value < min_value:
                    _LOG.warning("%s cannot be less than min value %s", name, min_value)
                    value = min_value

            if max_value is not None:
                assert type(max_value) is type(default_value)
                if value > max_value:
                    _LOG.warning("%s cannot be bigger than max value %s", name, max_value)
                    value = max_value
            return value

        except ValueError:
            _LOG.warning("bad value for %s, force to use the default value %s", name, default_value)
            return default_value

    @staticmethod
    def _env_commit_level(name: str, default_value: SolCommit, min_value: SolCommit | None = None) -> SolCommit:
        value = os.environ.get(name, None)
        if value is None:
            return default_value

        try:
            value = SolCommit.from_raw(value.lower())
            value_level = value.to_level()
            if (min_value is not None) and (value_level < min_value.to_level()):
                _LOG.warning(
                    "%s cannot be less than min value %s, force to use the default value %s",
                    name,
                    min_value,
                    default_value,
                )
                return default_value

            return value
        except ValueError:
            _LOG.warning("bad value for %s, force to use default value %s", name, default_value)
            return default_value

    ###################
    # Base settings

    @cached_property
    def sol_url_list(self) -> tuple[str, ...]:
        sol_url_list = self._split_str(os.environ.get(self.sol_url_name, ""))
        if not sol_url_list:
            _LOG.warning("%s is not defined, force to use the localhost", self.sol_url_name)
            sol_url_list = ["http://localhost:8899"]
        return tuple(sol_url_list)

    @property
    def random_sol_url(self) -> str:
        return self._random_from_list(self.sol_url_list)

    @staticmethod
    def _random_from_list(src_list: tuple[str, ...]) -> str:
        if len(src_list) == 0:
            return ""
        elif len(src_list) == 1:
            return src_list[0]
        return src_list[random.randrange(0, len(src_list))]

    @cached_property
    def sol_timeout_sec(self) -> float:
        return float(self._env_num(self.sol_timeout_sec_name, self._1min, 1, self._1hour))

    @cached_property
    def sol_ws_url_list(self) -> tuple[str, ...]:
        sol_ws_url_list = self._split_str(os.environ.get(self.sol_ws_url_name, ""))
        if not sol_ws_url_list:
            _LOG.debug(
                "%s is not defined, force to use the default value calculated from the %s",
                self.sol_ws_url_name,
                self.sol_url_name,
            )
            sol_ws_url_list = [_parse_sol_ws_url(s) for s in self.sol_url_list]
        return tuple(sol_ws_url_list)

    @property
    def random_sol_ws_url(self) -> str:
        return self._random_from_list(self.sol_ws_url_list)

    @cached_property
    def hide_sensitive_info(self) -> bool:
        return self._env_bool(self.hide_sensitive_info_name, True)

    @cached_property
    def sensitive_info_list(self) -> tuple[str, ...]:
        res_list = (
            list(self.sol_url_list)
            + list(self.pyth_url_list)
            + list(self.sol_ws_url_list)
            + list(self.pyth_ws_url_list)
            + list(self.ch_dsn_list)
            + [self.hvac_url, self.hvac_mount, self.hvac_token, self.hvac_path]
            + [self.pg_host, self.pg_db, self.pg_user, self.pg_password]
        )
        res_set = set([item for item in res_list if item])
        res_list = sorted(res_set, key=lambda x: len(x), reverse=True)
        return tuple(res_list)

    @cached_property
    def enable_private_api(self) -> bool:
        return self._env_bool(self.enable_private_api_name, False)

    @cached_property
    def enable_send_tx_api(self) -> bool:
        return self._env_bool(self.enable_send_tx_api_name, True)

    @cached_property
    def max_emulate_evm_step_cnt(self) -> int:
        return self._env_num(self.max_emulate_evm_step_cnt_name, 500_000, 1000)

    @cached_property
    def debug_cmd_line(self) -> bool:
        return self._env_bool(self.debug_cmd_line_name, False)

    #########################
    # Statistic configuration

    @property
    def stat_ip(self) -> str:
        return self.base_service_ip

    @property
    def stat_port(self) -> int:
        return self.base_service_port + 3

    @property
    def stat_public_port(self) -> int:
        return 8888

    @cached_property
    def gather_stat(self) -> bool:
        return self._env_bool(self.gather_stat_name, False)

    #########################
    # Proxy configuration

    @cached_property
    def rpc_private_ip(self) -> str:
        return os.environ.get(self.rpc_private_ip_name, self.base_service_ip)

    @cached_property
    def rpc_private_port(self) -> int:
        return self._env_num(self.rpc_private_port_name, self.rpc_public_port + 1, 8000, 25000)

    @cached_property
    def rpc_public_port(self) -> int:
        return self._env_num(self.rpc_public_port_name, 9090, 8000, 25000)

    @cached_property
    def rpc_process_cnt(self) -> int:
        return self._env_num(self.rpc_process_cnt_name, os.cpu_count(), 1)

    @cached_property
    def rpc_worker_cnt(self) -> int:
        return self._env_num(self.rpc_worker_cnt_name, 1, 1)

    #####################
    # Base Service settings
    @cached_property
    def base_service_ip(self) -> str:
        return os.environ.get(self.base_service_ip_name, "127.0.0.1")

    @cached_property
    def base_service_port(self) -> int:
        return self._env_num(self.base_service_port_name, 9100, 8000, 25000)

    #####################
    # Mempool settings

    @cached_property
    def mp_ip(self) -> str:
        return self.base_service_ip

    @cached_property
    def mp_port(self) -> int:
        return self.base_service_port

    @cached_property
    def exec_ip(self) -> str:
        return self.base_service_ip

    @cached_property
    def exec_port(self) -> int:
        return self.base_service_port + 1

    @cached_property
    def op_resource_ip(self) -> str:
        return self.base_service_ip

    @cached_property
    def op_resource_port(self) -> int:
        return self.base_service_port + 2

    @cached_property
    def mp_capacity(self) -> int:
        return self._env_num(self.mp_capacity_name, 4096, 10, 4096 * 1024)

    @cached_property
    def mp_capacity_high_watermark(self) -> float:
        return self._env_num(self.mp_capacity_high_watermark_name, 0.9, 0, 1)

    @cached_property
    def mp_eviction_timeout_sec(self) -> int:
        return self._env_num(self.mp_eviction_timeout_sec_name, 3 * self._1hour, 10)

    @cached_property
    def mp_gas_price_min_window(self) -> int:
        return self._env_num(self.mp_gas_price_min_window_name, 10, 1, 1000)

    @cached_property
    def mp_cache_life_sec(self) -> int:
        return self._env_num(self.mp_cache_life_sec_name, 30 * self._1min, 15, self._1hour)

    @cached_property
    def mp_exec_process_cnt(self) -> int:
        return self._env_num(self.mp_exec_process_cnt_name, max(os.cpu_count() // 2, 1), 1)

    @cached_property
    def mp_exec_worker_cnt(self) -> int:
        return self._env_num(self.mp_exec_worker_cnt_name, 1, 1)

    @cached_property
    def mp_skip_stuck_tx(self) -> bool:
        return self._env_bool(self.mp_skip_stuck_tx_name, False)

    @cached_property
    def mp_lost_alt_timeout_sec(self) -> int:
        return self._env_num(self.mp_lost_alt_timeout_sec_name, 6 * self._1hour, 1 * self._1hour)

    ########################
    # Neon Core API settings

    @property
    def neon_core_api_ip(self) -> str:
        return self.base_service_ip

    @cached_property
    def neon_core_api_port(self) -> int:
        return self.base_service_port + 4

    @cached_property
    def neon_core_api_server_cnt(self) -> int:
        return self._env_num(self.neon_core_api_server_cnt_name, 1, 1)

    @cached_property
    def sol_key_for_evm_cfg(self) -> SolPubKey:
        return self._env_sol_acct(self.sol_key_for_evm_cfg_name)

    ###########################
    # Postgres DB settings

    @cached_property
    def pg_host(self) -> str:
        return os.environ.get(self.pg_host_name, self._pg_null_value)

    @cached_property
    def pg_db(self) -> str:
        return os.environ.get(self.pg_db_name, self._pg_null_value)

    @cached_property
    def pg_user(self) -> str:
        return os.environ.get(self.pg_user_name, self._pg_null_value)

    @cached_property
    def pg_password(self) -> str:
        return os.environ.get(self.pg_password_name, self._pg_null_value)

    @cached_property
    def pg_timeout_sec(self) -> int:
        return self._env_num(self.pg_timeout_sec_name, 0, 0)

    @cached_property
    def pg_conn_cnt(self) -> int:
        return self._env_num(self.pg_conn_cnt_name, max(os.cpu_count() // 2, 5), 5)

    #################################
    # Transaction execution settings

    @property
    def retry_on_fail(self) -> int:
        value = self._retry_on_fail
        return value + random.randint(0, value)

    @cached_property
    def _retry_on_fail(self) -> int:
        return self._env_num(self.retry_on_fail_name, 64, 1, 1024)

    @cached_property
    def commit_timeout_sec(self) -> int:
        return self._env_num(self.commit_timeout_sec_name, int(MIN_FINALIZE_SEC), 1.2, 60)

    @cached_property
    def commit_type(self) -> SolCommit:
        return self._env_commit_level(self.commit_level_name, SolCommit.Confirmed, SolCommit.Confirmed)

    @cached_property
    def max_tx_account_cnt(self) -> int:
        return self._env_num(self.max_tx_account_cnt_name, 64, 20, 256)

    #####################
    # Gas-Price settings

    @cached_property
    def _pyth_url_list(self) -> list[str]:
        return self._split_str(os.environ.get(self.pyth_url_name, ""))

    @cached_property
    def pyth_url_list(self) -> tuple[str, ...]:
        pyth_url_list = self._pyth_url_list
        if not pyth_url_list:
            _LOG.debug(
                "%s is not defined, force to use the default value: "
                "(PYTHNET_HTTP_ENDPOINT, SOLANA_MAINNET_HTTP_ENDPOINT, SOLANA_DEVNET_HTTP_ENDPOINT) + sol_url_list",
                self.pyth_url_name,
            )
            pyth_url_list = (
                [PYTHNET_HTTP_ENDPOINT]
                + list(self.sol_url_list)
                + [SOLANA_MAINNET_HTTP_ENDPOINT, SOLANA_DEVNET_HTTP_ENDPOINT]
            )
        return tuple(pyth_url_list)

    @cached_property
    def pyth_ws_url_list(self) -> tuple[str, ...]:
        pyth_ws_url_list = self._split_str(os.environ.get(self.pyth_ws_url_name, ""))
        if not pyth_ws_url_list:
            pyth_url_list = self._pyth_url_list
            if not pyth_url_list:
                _LOG.debug(
                    "%s is not defined, force to use the default value: "
                    "(PYTHNET_WS_ENDPOINT, SOLANA_MAINNET_WS_ENDPOINT, SOLANA_DEVNET_WS_ENDPOINT) + sol_ws_url_list",
                    self.pyth_ws_url_name,
                )
                pyth_ws_url_list = (
                    [PYTHNET_WS_ENDPOINT]
                    + list(self.sol_ws_url_list)
                    + [SOLANA_MAINNET_WS_ENDPOINT, SOLANA_DEVNET_WS_ENDPOINT]
                )
            else:
                _LOG.debug(
                    "%s is not defined, force to use the default value calculated from the %s",
                    self.pyth_ws_url_name,
                    self.pyth_url_name,
                )
                pyth_ws_url_list = [_parse_sol_ws_url(s) for s in self.pyth_url_list]
        return tuple(pyth_ws_url_list)

    @cached_property
    def operator_fee(self) -> Decimal:
        return self._env_num(self.operator_fee_name, Decimal("0.1"), Decimal("0.0"), Decimal("100.0"))

    @cached_property
    def cu_limit(self) -> int:
        cb_prog = SolCbProg()
        return self._env_num(self.cu_limit_name, cb_prog.MaxCuLimit, cb_prog.DefCuLimit // 5, cb_prog.MaxCuLimit)

    @cached_property
    def cu_price(self) -> int:
        return self._env_num(self.cu_price_name, 0, 0, 1_000_000)

    @cached_property
    def simple_cu_price(self) -> int:
        return self._env_num(self.simple_cu_price_name, 0, 0, 1_000_000)

    @cached_property
    def max_cu_price_mult(self) -> int:
        return self._env_num(self.max_cu_price_mult_name, 16, 1, 128)

    @cached_property
    def min_gas_price(self) -> int | None:
        """Minimal gas price to accept tx into the mempool"""
        gas_price = self._env_num(self.min_gas_price_name, -1, 0, 100_000_000)
        if gas_price < 0:
            return None
        return gas_price * (10**9)

    @cached_property
    def min_wo_chain_id_gas_price(self) -> int:
        """Minimal gas price for txs without chain-id"""
        gas_price = self._env_num(self.min_wo_chain_id_gas_price_name, 10, 0, 100_000_000)
        return gas_price * (10**9)

    @cached_property
    def const_gas_price(self) -> int | None:
        min_gas_price = (self.min_gas_price or 0) // (10**9)
        const_gas_price = self._env_num(self.const_gas_price_name, -1, min_gas_price, 100_000_000)
        if const_gas_price < 0:
            return None
        elif const_gas_price < min_gas_price:
            _LOG.warning(
                "%s is less than %s, force to use %s",
                self.const_gas_price_name,
                self.min_gas_price_name,
                self.min_gas_price_name,
            )
            const_gas_price = min_gas_price
        return const_gas_price * (10**9)

    #############################
    # Operator resource settings

    @cached_property
    def holder_size(self) -> int:
        return self._env_num(self.holder_size_name, 256 * 1024, 1024, 10 * 1024 * 1024)

    @cached_property
    def min_op_balance_to_warn(self) -> int:
        return self._env_num(self.min_op_balance_to_warn_name, 9_000_000_000, 1)

    @cached_property
    def min_op_balance_to_err(self) -> int:
        return self._env_num(self.min_op_balance_to_err_name, 1_000_000_000, 1)

    @cached_property
    def perm_account_id(self) -> int:
        return self._env_num(self.perm_account_id_name, 1, 1, 128)

    @cached_property
    def perm_account_limit(self) -> int:
        return self._env_num(self.perm_account_limit_name, 2, 1, 128)

    ########################################
    # HashiCorp Vault to store operator keys

    @cached_property
    def hvac_url(self) -> str | None:
        return os.environ.get(self.hvac_url_name, None)

    @cached_property
    def hvac_token(self) -> str | None:
        return os.environ.get(self.hvac_token_name, None)

    @cached_property
    def hvac_mount(self) -> str | None:
        return os.environ.get(self.hvac_mount_name, None)

    @cached_property
    def hvac_path(self) -> str:
        return os.environ.get(self.hvac_path_name, "")

    ####################
    # Indexing settings

    @cached_property
    def start_slot(self) -> StartSlot.Type:
        return self._env_start_slot(self.start_slot_name, StartSlot.Latest)

    @cached_property
    def indexer_poll_block_cnt(self) -> int:
        return self._env_num(self.indexer_poll_block_cnt_name, 32, 3, 1024)

    @cached_property
    def indexer_check_msec(self) -> int:
        return self._env_num(self.indexer_check_msec_name, 200, 50, 10_000)

    @cached_property
    def stuck_object_blockout(self) -> int:
        return self._env_num(self.stuck_object_blockout_name, 64, 16, 1024)

    @cached_property
    def stuck_object_validate_blockout(self) -> int:
        return self._env_num(self.stuck_object_validate_blockout_name, 1024, 512, 1024 * 1024)

    @cached_property
    def alt_freeing_depth(self) -> int:
        return self._env_num(self.alt_freeing_depth_name, 2048, 512, 1024)

    @cached_property
    def metrics_log_skip_cnt(self) -> int:
        return self._env_num(self.metrics_log_skip_cnt_name, 1000, 1, 100_000)

    @cached_property
    def op_key_set(self) -> set[SolPubKey]:
        return self._env_sol_acct_set(self.op_key_list_name)

    ######################################
    # Integration Indexer with Tracer API

    @cached_property
    def slot_processing_delay(self) -> int:
        """Slot processing delay relative to the last confirmed slot on Tracer API node"""
        return self._env_num(self.slot_processing_delay_name, 0, 0, 64)

    @cached_property
    def ch_dsn_list(self) -> tuple[str, ...]:
        """List of DSN addresses of clickhouse servers used by Tracer API node"""
        return tuple(self._env_dsn_list(self.clickhouse_dsn_list_name))

    ###########################
    # ReIndexing configuration

    @cached_property
    def reindex_start_slot(self) -> StartSlot.Type:
        return self._env_start_slot(self.reindex_start_slot_name, StartSlot.Continue)

    @cached_property
    def reindex_thread_cnt(self) -> int:
        return self._env_num(self.reindex_thread_cnt_name, 3, 0, 128)

    @cached_property
    def reindex_range_len(self) -> int:
        return self._env_num(
            self.reindex_block_cnt_in_range_name,
            int(self._1hour / ONE_BLOCK_SEC),
            int((10 * self._1min) / ONE_BLOCK_SEC),
            int(self._1day / ONE_BLOCK_SEC),
        )

    @cached_property
    def reindex_max_range_cnt(self) -> int:
        return self._env_num(self.reindex_max_range_cnt_name, 128, 1, 256)

    # #######################################
    # # gas-less transactions configuration
    #
    # @cached_property
    # def gas_tank_parallel_request_cnt(self) -> int:
    #     return self._env_num(self.gas_tank_parallel_request_cnt_name, 10, 1, 100)
    #
    # @cached_property
    # def gas_tank_poll_tx_cnt(self) -> int:
    #     return self._env_num(self.gas_tank_poll_tx_count_name, 1000, 1, 1000)
    #
    # @cached_property
    # def gas_less_tx_max_nonce(self) -> int:
    #     return self._env_num(self.gas_less_max_tx_nonce_name, 5, 1, 1000)
    #
    # @cached_property
    # def gas_less_tx_max_gas(self) -> int:
    #     # Estimated gas on Mora = 18 mln
    #     return self._env_num(self.gas_less_max_gas_name, 20_000_000, 21_000, 1_000_000_000)

    ##############################
    # testing settings

    @cached_property
    def fuzz_fail_pct(self) -> int:
        return self._env_num(self.fuzz_fail_pct_name, 0, 0, 100)

    @cached_method
    def to_string(self) -> str:
        cfg_dict = {
            self.hide_sensitive_info_name: self.hide_sensitive_info,
            "NEON_EVM_PROGRAM": NEON_EVM_PROGRAM_ID,
            "SOLANA_BLOCK_SEC": ONE_BLOCK_SEC,
            "MINIMAL_FINALIZATION_SEC": MIN_FINALIZE_SEC,
            "SOLANA_PACKET_SIZE": SOL_PACKET_SIZE,
            "DEFAULT_TOKEN_NAME": DEFAULT_TOKEN_NAME,
            "CHAIN_TOKEN_NAME": CHAIN_TOKEN_NAME,
            self.sol_url_name: self.sol_url_list,
            self.sol_ws_url_name: self.sol_ws_url_list,
            self.sol_timeout_sec_name: self.sol_timeout_sec,
            self.enable_private_api_name: self.enable_private_api,
            self.enable_send_tx_api_name: self.enable_send_tx_api,
            self.max_emulate_evm_step_cnt_name: self.max_emulate_evm_step_cnt,
            self.gather_stat_name: self.gather_stat,
            self.debug_cmd_line_name: self.debug_cmd_line,
            # Proxy configuration
            self.rpc_private_ip_name: self.rpc_private_ip,
            self.rpc_private_port_name: self.rpc_private_port,
            self.rpc_public_port_name: self.rpc_public_port,
            self.rpc_process_cnt_name: self.rpc_process_cnt,
            self.rpc_worker_cnt_name: self.rpc_worker_cnt,
            # Base service settings:
            self.base_service_ip_name: self.base_service_ip,
            self.base_service_port_name: self.base_service_port,
            # Mempool settings
            self.mp_capacity_name: self.mp_capacity,
            self.mp_capacity_high_watermark_name: self.mp_capacity_high_watermark,
            self.mp_eviction_timeout_sec_name: self.mp_eviction_timeout_sec,
            self.mp_gas_price_min_window_name: self.mp_gas_price_min_window,
            self.mp_cache_life_sec_name: self.mp_cache_life_sec,
            self.mp_exec_process_cnt_name: self.mp_exec_process_cnt,
            self.mp_exec_worker_cnt_name: self.mp_exec_worker_cnt,
            self.mp_skip_stuck_tx_name: self.mp_skip_stuck_tx,
            self.mp_lost_alt_timeout_sec_name: self.mp_lost_alt_timeout_sec,
            # Neon Core API settings
            self.neon_core_api_server_cnt_name: self.neon_core_api_server_cnt,
            self.sol_key_for_evm_cfg_name: self.sol_key_for_evm_cfg,
            # Postgres DB settings
            self.pg_host_name: self.pg_host,
            self.pg_db_name: self.pg_db,
            self.pg_user_name: self.pg_user,
            self.pg_password_name: self.pg_password,
            self.pg_timeout_sec_name: self.pg_timeout_sec,
            self.pg_conn_cnt_name: self.pg_conn_cnt,
            # Transaction execution settings
            self.retry_on_fail_name: self._retry_on_fail,
            self.commit_timeout_sec_name: self.commit_timeout_sec,
            self.commit_level_name: self.commit_type,
            self.max_tx_account_cnt_name: self.max_tx_account_cnt,
            # Gas price settings
            self.pyth_url_name: self.pyth_url_list,
            self.pyth_ws_url_name: self.pyth_ws_url_list,
            self.operator_fee_name: self.operator_fee,
            self.cu_limit_name: self.cu_limit,
            self.cu_price_name: self.cu_price,
            self.simple_cu_price_name: self.simple_cu_price,
            self.max_cu_price_mult_name: self.max_cu_price_mult,
            self.min_gas_price_name: self.min_gas_price,
            self.min_wo_chain_id_gas_price_name: self.min_wo_chain_id_gas_price,
            self.const_gas_price_name: self.const_gas_price,
            # Operator resources
            self.holder_size_name: self.holder_size,
            self.min_op_balance_to_warn_name: self.min_op_balance_to_warn,
            self.min_op_balance_to_err_name: self.min_op_balance_to_err,
            self.perm_account_id_name: self.perm_account_id,
            self.perm_account_limit_name: self.perm_account_limit,
            # HashiCorp Vault settings
            self.hvac_url_name: self.hvac_url,
            self.hvac_token_name: self.hvac_token,
            self.hvac_path_name: self.hvac_path,
            self.hvac_mount_name: self.hvac_mount,
            # Indexing settings
            self.start_slot_name: self.start_slot,
            self.indexer_poll_block_cnt_name: self.indexer_poll_block_cnt,
            self.indexer_check_msec_name: self.indexer_check_msec,
            self.stuck_object_blockout_name: self.stuck_object_blockout,
            self.stuck_object_validate_blockout_name: self.stuck_object_validate_blockout,
            self.alt_freeing_depth_name: self.alt_freeing_depth,
            self.metrics_log_skip_cnt_name: self.metrics_log_skip_cnt,
            # Integration Indexer with Tracer API
            self.slot_processing_delay_name: self.slot_processing_delay,
            self.clickhouse_dsn_list_name: self.ch_dsn_list,
            # Reindexing settings
            self.reindex_start_slot_name: self.reindex_start_slot,
            self.reindex_thread_cnt_name: self.reindex_thread_cnt,
            self.reindex_block_cnt_in_range_name: self.reindex_range_len,
            self.reindex_max_range_cnt_name: self.reindex_max_range_cnt,
            # # Gas-less transaction configuration
            # self.gas_tank_parallel_request_cnt_name: self.gas_tank_parallel_request_cnt,
            # self.gas_tank_poll_tx_count_name: self.gas_tank_poll_tx_cnt,
            # self.gas_less_max_tx_nonce_name: self.gas_less_tx_max_nonce,
            # self.gas_less_max_gas_name: self.gas_less_tx_max_gas,
            # Testing settings
            self.fuzz_fail_pct_name: self.fuzz_fail_pct,
        }

        return str_fmt_object(self._filter_sensitive_info(cfg_dict))

    def _filter_sensitive_info(self, cfg_dict: dict) -> dict:
        if not self.hide_sensitive_info:
            return cfg_dict

        sensitive_info_list = self.sensitive_info_list
        hide_key_list: list[str] = list()

        def _is_sensitive_info(_value: str) -> bool:
            return _value in sensitive_info_list

        for key, value in cfg_dict.items():
            if isinstance(value, (list, set, tuple)):
                for item in value:
                    if _is_sensitive_info(item):
                        hide_key_list.append(key)
                        break
            elif _is_sensitive_info(value):
                hide_key_list.append(key)

        for key in hide_key_list:
            cfg_dict[key] = "?*****?"

        return cfg_dict

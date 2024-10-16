from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Sequence, Final, TypeVar

from .api import (
    CoreApiResp,
    CoreApiResultCode,
    CoreApiTxModel,
    CoreApiBlockModel,
    CoreApiBuildModel,
    EvmConfigModel,
    BpfLoader2ExecModel,
    BpfLoader2ProgModel,
    HolderAccountModel,
    HolderAccountRequest,
    NeonAccountStatus,
    NeonAccountModel,
    NeonAccountListRequest,
    NeonStorageAtRequest,
    NeonContractRequest,
    NeonContractModel,
    OpEarnAccountModel,
    EmulNeonCallExitCode,
    EmulSolAccountModel,
    EmulSolTxListResp,
    EmulSolTxInfo,
    EmulSolTxListRequest,
    EmulNeonCallResp,
    EmulNeonCallRequest,
    EmulTraceCfgModel,
    EmulNeonAccountModel,
)
from ..config.config import Config
from ..ethereum.commit_level import EthCommit
from ..ethereum.errors import EthError
from ..ethereum.hash import EthAddress, EthHash32
from ..http.client import HttpClient
from ..http.errors import PydanticValidationError
from ..http.utils import HttpURL
from ..neon.account import NeonAccount
from ..neon.block import NeonBlockHdrModel
from ..neon.neon_program import NeonProg
from ..solana.account import SolAccountModel
from ..solana.hash import SolBlockHash
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana_rpc.client import SolClient
from ..stat.client_rpc import RpcStatClient, RpcClientRequest
from ..utils.cached import cached_method, ttl_cached_method
from ..utils.json_logger import log_msg, get_ctx
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)
_RespType = TypeVar("_RespType", bound=BaseModel)


class CoreApiClient(HttpClient):
    _stat_name: Final[str] = "NeonCoreApi"

    def __init__(self, cfg: Config, sol_client: SolClient, stat_client: RpcStatClient) -> None:
        super().__init__(cfg)

        client_cnt = len(cfg.sol_url_list) * cfg.neon_core_api_server_cnt
        base_port = cfg.neon_core_api_port
        for idx in range(client_cnt):
            port = base_port + idx
            self.connect(host=cfg.neon_core_api_ip, port=port, path="/api/")

        self.set_timeout_sec(120).set_max_retry_cnt(30)

        self._stat_client = stat_client
        self._sol_client = sol_client
        self._evm_cfg = EvmConfigModel.default()

        self._raise_for_status = False

    async def get_evm_cfg(self) -> EvmConfigModel:
        try:
            exec_addr = await self._get_evm_exec_addr()

            # Load the header of the executable account to get the deployed slot
            min_size = BpfLoader2ExecModel.minimum_size
            acct = await self._sol_client.get_account(exec_addr, min_size)
            if acct.is_empty:
                raise ValueError(f"Account {exec_addr} doesn't exists")

            exec_info = BpfLoader2ExecModel.from_data(acct.data)

            # Don't try to update EVM config, if we have the same version of the executable account
            if exec_info.deployed_slot == self._evm_cfg.deployed_slot:
                return self._evm_cfg

            _LOG.debug("get EVM config on the slot: %s", exec_info.deployed_slot)
            resp: CoreApiResp = await self._send_request("config")
            if resp.result != CoreApiResultCode.Success:
                _LOG.error(
                    "get error on reading EVM config: %s",
                    resp.error,
                    extra=self._msg_filter,
                )
                return self._evm_cfg
            evm_cfg = EvmConfigModel.from_dict(resp.value, deployed_slot=exec_info.deployed_slot)

            _LOG.debug("get EVM config: %s", evm_cfg)
            self._evm_cfg = evm_cfg
            return self._evm_cfg
        except BaseException as exc:
            _LOG.error("error on reading EVM config", exc_info=exc)
            return EvmConfigModel.default()

    @cached_method
    async def get_core_api_version(self) -> str:
        method = "build-info"

        request = RpcClientRequest.from_raw(
            data="",
            stat_client=self._stat_client,
            stat_name=self._stat_name,
            method=method,
        )

        resp_json = await self._send_client_request(request, path=HttpURL(method))
        try:
            resp = CoreApiBuildModel.from_json(resp_json)
            return "Neon-Core-API/v" + resp.crate_info.version + "-" + resp.version_control.commit_id

        except PydanticValidationError as exc:
            _LOG.debug("bad response from neon-core-api", exc_info=exc, extra=self._msg_filter)

        return "Neon-Core-API/UNKNOWN"

    async def get_holder_account(self, address: SolPubKey) -> HolderAccountModel:
        req = HolderAccountRequest.from_raw(address)
        resp: CoreApiResp = await self._send_request("holder", req)
        if resp.error:
            _LOG.error(
                log_msg(
                    "error on reading holder account {Address}: {Error}",
                    Address=address,
                    Error=resp.error,
                ),
                extra=self._msg_filter,
            )
            return HolderAccountModel.new_empty(address)
        return HolderAccountModel.from_dict(address, resp.value)

    async def get_neon_account_list(
        self,
        account_list: Sequence[NeonAccount],
        block: NeonBlockHdrModel | None,
    ) -> tuple[NeonAccountModel, ...]:
        req = NeonAccountListRequest.from_raw(account_list, self._get_slot(block))
        resp: CoreApiResp = await self._send_request("balance", req)
        if resp.error:
            msg = log_msg(
                "get error on reading balance accounts {Accounts}: {Error}",
                Accounts=account_list,
                Error=resp.error,
            )
            _LOG.error(msg, extra=self._msg_filter)
            return tuple([NeonAccountModel.new_empty(acct) for acct in account_list])

        return tuple([NeonAccountModel.from_dict(data, account=a) for a, data in zip(account_list, resp.value)])

    async def get_neon_account(self, account: NeonAccount, block: NeonBlockHdrModel | None) -> NeonAccountModel:
        acct_list = await self.get_neon_account_list([account], block)
        return acct_list[0]

    async def get_state_tx_cnt(self, account: NeonAccount, block: NeonBlockHdrModel | None = None) -> int:
        acct = await self.get_neon_account(account, block)
        return acct.state_tx_cnt

    async def get_neon_contract(self, account: NeonAccount, block: NeonBlockHdrModel | None) -> NeonContractModel:
        req = NeonContractRequest(contract=account.eth_address, slot=self._get_slot(block), id=get_ctx())
        resp: CoreApiResp = await self._send_request("contract", req)
        return NeonContractModel.from_dict(resp.value[0], account=account)

    async def get_storage_at(self, contract: EthAddress, index: int, block: NeonBlockHdrModel | None) -> EthHash32:
        req = NeonStorageAtRequest(contract=contract, index=index, slot=self._get_slot(block), id=get_ctx())
        resp: CoreApiResp = await self._send_request("storage", req)
        return EthHash32.from_raw(bytes(resp.value))

    async def get_earn_account(
        self,
        evm_cfg: EvmConfigModel,
        operator_key: SolPubKey,
        account: NeonAccount,
        _block: NeonBlockHdrModel | None,
    ) -> OpEarnAccountModel:
        seed_list = (
            evm_cfg.account_seed_version.to_bytes(1, byteorder="little"),
            operator_key.to_bytes(),
            account.eth_address.to_bytes(),
            account.chain_id.to_bytes(32, byteorder="big"),
        )

        token_sol_addr, _ = SolPubKey.find_program_address(seed_list, NeonProg.ID)

        # TODO: move to core-api
        prefix_len: Final[int] = 1 + 1  # tag + version
        owner_len: Final[int] = SolPubKey.KeySize
        addr_len: Final[int] = EthAddress.HashSize
        chain_id_len: Final[int] = 8
        balance_len: Final[int] = 32
        balance_offset: Final[int] = prefix_len + owner_len + addr_len + chain_id_len

        sol_acct = await self._sol_client.get_account(token_sol_addr)
        if not sol_acct.is_empty:
            status = NeonAccountStatus.Ok
            balance = int.from_bytes(
                sol_acct.data[balance_offset : balance_offset + balance_len],
                byteorder="little",
            )
        else:
            status = NeonAccountStatus.Empty
            balance = 0

        return OpEarnAccountModel(
            status=status,
            operator_key=operator_key,
            neon_account=account,
            token_sol_address=token_sol_addr,
            balance=balance,
        )

    async def emulate_neon_call(
        self,
        evm_cfg: EvmConfigModel,
        tx: CoreApiTxModel,
        *,
        check_result: bool,
        sender_balance: int | None = None,
        preload_sol_address_list: tuple[SolPubKey, ...] = tuple(),
        sol_account_dict: dict[SolPubKey, SolAccountModel | None] | None = None,
        emulator_block = CoreApiBlockModel.default(),
        block: NeonBlockHdrModel | None = None,
    ) -> EmulNeonCallResp:
        emul_sol_acct_dict = dict()
        if sol_account_dict:
            emul_sol_acct_dict = {addr: EmulSolAccountModel.from_raw(raw) for addr, raw in sol_account_dict.items()}

        if emulator_block.is_empty:
            emulator_block = None
        else:
            _LOG.debug("use predefined block: %d, %d", emulator_block.slot, emulator_block.timestamp)

        emul_neon_acct_dict = dict()
        if (tx.nonce is not None) or (sender_balance is not None):
            emul_balance = sender_balance + tx.cost if sender_balance is not None else None
            emul_neon_acct_dict[tx.from_address] = EmulNeonAccountModel(nonce=tx.nonce, balance=emul_balance)

        emul_trace_cfg = None
        if emul_neon_acct_dict or emulator_block:
            emul_trace_cfg = EmulTraceCfgModel(neon_account_dict=emul_neon_acct_dict, block=emulator_block)

        req = EmulNeonCallRequest(
            tx=tx,
            evm_step_limit=self._cfg.max_emulate_evm_step_cnt,
            token_list=evm_cfg.token_list,
            trace_cfg=emul_trace_cfg,
            preload_sol_address_list=list(preload_sol_address_list),
            sol_account_dict=emul_sol_acct_dict,
            slot=self._get_slot(block),
            id=get_ctx(),
        )
        resp: EmulNeonCallResp = await self._send_request("emulate", req, EmulNeonCallResp)
        if check_result:
            self._check_emulator_result(resp)
        return resp

    async def emulate_sol_tx_list(
        self,
        cu_limit: int,
        account_cnt_limit: int,
        blockhash: SolBlockHash,
        tx_list: Sequence[SolTx],
    ) -> tuple[EmulSolTxInfo, ...]:
        req = EmulSolTxListRequest(
            cu_limit=cu_limit,
            account_cnt_limit=account_cnt_limit,
            verify=False,
            blockhash=blockhash.to_bytes(),
            tx_list=tuple(map(lambda tx: tx.to_bytes(), tx_list)),
            id=get_ctx(),
        )

        resp: EmulSolTxListResp = await self._send_request("simulate_solana", req, EmulSolTxListResp)
        return tuple([EmulSolTxInfo(tx, meta) for tx, meta in zip(tx_list, resp.meta_list)])

    async def _send_request(
        self,
        method: str,
        request: BaseModel | None = None,
        resp_type: type[_RespType] | None = None,
    ) -> _RespType:
        request = RpcClientRequest.from_raw(
            data=request.to_json() if request else "",
            stat_client=self._stat_client,
            stat_name=self._stat_name,
            method=method,
        )

        with request:
            for retry in itertools.count():
                if retry >= self._max_retry_cnt:
                    raise EthError("No connection to NeonCoreApi. Maximum retry count reached.")
                if retry > 0:
                    _LOG.debug("attempt %d to repeat %s...", retry + 1, method)

                request.start_timer()
                resp_json = await self._send_client_request(request, path=HttpURL(method))
                try:
                    resp = CoreApiResp.from_json(resp_json)

                except PydanticValidationError as exc:
                    _LOG.debug("bad response from neon-core-api", exc_info=exc, extra=self._msg_filter)
                    request.commit_stat(is_error=True)
                    await asyncio.sleep(0.2)
                    continue

                if (resp.error_code or 0) == 113:  # Solana client error
                    request.commit_stat(is_error=True)
                    await asyncio.sleep(0.2)
                    continue

                if resp_type is None:
                    return resp
                elif resp.error:
                    raise EthError(resp.error)

                return resp_type.from_dict(resp.value)

    @ttl_cached_method(ttl_sec=60)
    async def _get_evm_exec_addr(self) -> SolPubKey:
        # Load the BPF program account to get the address of the BPF executable account
        acct = await self._sol_client.get_account(NeonProg.ID)
        if acct.is_empty:
            raise ValueError(f"Account {NeonProg.ID} doesn't exists")

        prog = BpfLoader2ProgModel.from_data(acct.data)
        return prog.exec_address

    def _check_emulator_result(self, resp: EmulNeonCallResp) -> None:
        if resp.exit_code == EmulNeonCallExitCode.Revert:
            revert_data = resp.result.to_string()
            _LOG.debug("got reverted result with data: %s", revert_data)

            if not (result_value := self._decode_revert_message(revert_data[2:])):  # remove 0x
                raise EthError(code=3, message="execution reverted", data=revert_data)
            else:
                raise EthError(
                    code=3,
                    message="execution reverted: " + result_value,
                    data=revert_data,
                )

        if resp.exit_code != EmulNeonCallExitCode.Succeed:
            _LOG.debug("got failed emulate exit code: %s", resp.exit_code)
            raise EthError(code=3, message=resp.exit_code)

    @staticmethod
    def _decode_revert_message(data: str) -> str | None:
        if not data:
            return None

        if (data_len := len(data)) < 8:
            raise EthError(
                code=3,
                message=f"Too less bytes to decode revert signature: {data_len}",
                data=data,
            )

        if data[:8] == "4e487b71":  # keccak256("Panic(uint256)")
            return None

        if data[:8] != "08c379a0":  # keccak256("Error(string)")
            _LOG.debug(f"failed to decode revert_message, unknown revert signature: {data[:8]}")
            return None

        if data_len < 8 + 64:
            raise EthError(
                code=3,
                message=f"Too less bytes to decode revert msg offset: {data_len}",
                data=data,
            )
        offset = int(data[8 : 8 + 64], 16) * 2

        if data_len < 8 + offset + 64:
            raise EthError(
                code=3,
                message=f"Too less bytes to decode revert msg len: {data_len}",
                data=data,
            )
        length = int(data[8 + offset : 8 + offset + 64], 16) * 2

        if data_len < 8 + offset + 64 + length:
            raise EthError(
                code=3,
                message=f"Too less bytes to decode revert msg: {data_len}",
                data=data,
            )

        message = str(bytes.fromhex(data[8 + offset + 64 : 8 + offset + 64 + length]), "utf8")
        return message

    def _get_slot(self, block: NeonBlockHdrModel | None) -> int | None:
        if block:
            if block.commit in (EthCommit.Latest, EthCommit.Pending):
                return None
            elif self._cfg.ch_dsn_list:
                return block.slot
        return None

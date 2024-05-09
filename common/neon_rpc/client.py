from __future__ import annotations

import logging
from typing import Sequence

from .api import (
    CoreApiResp,
    CoreApiResultCode,
    EvmConfigModel,
    BpfLoader2ExecModel,
    BpfLoader2ProgModel,
    CoreApiBuildModel,
    HolderAccountModel,
    NeonAccountModel,
    HolderAccountRequest,
    NeonAccountListRequest,
    EmulatorResp,
    EmulatorRequest,
    EmulatorTxModel,
    EmulatorExitCode,
    NeonStorageAtRequest,
    NeonContractRequest,
    NeonContractModel,
    EmulatorSolAccount,
)
from ..config.config import Config
from ..ethereum.commit_level import EthCommit
from ..ethereum.errors import EthError
from ..ethereum.hash import EthAddressField, EthAddress, EthHash32
from ..neon.account import NeonAccount
from ..neon.block import NeonBlockHdrModel
from ..neon.neon_program import NeonProg
from ..neon.transaction_model import NeonTxModel
from ..simple_app_data.client import SimpleAppDataClient
from ..solana.account import SolAccountModel
from ..solana.pubkey import SolPubKey
from ..solana_rpc.client import SolClient
from ..utils.cached import cached_method, ttl_cached_method
from ..utils.json_logger import log_msg

_LOG = logging.getLogger(__name__)


class CoreApiClient(SimpleAppDataClient):
    def __init__(self, cfg: Config, sol_client: SolClient) -> None:
        super().__init__(cfg)

        client_cnt = len(cfg.sol_url_list)
        base_port = cfg.neon_core_api_port
        for idx in range(client_cnt):
            port = base_port + idx
            self.connect(host="127.0.0.1", port=port, path="/api/")

        self.set_timeout_sec(5).set_max_retry_cnt(30)

        self._sol_client = sol_client
        self._evm_cfg = EvmConfigModel.default()

    async def get_evm_cfg(self) -> EvmConfigModel:
        try:
            exec_addr = await self._get_evm_exec_addr()

            # Load the header of the executable account to get the deployed slot
            min_size = BpfLoader2ExecModel.minimum_size
            acct_info = await self._sol_client.get_account(exec_addr, min_size)
            if acct_info.is_empty:
                raise ValueError(f"Account {exec_addr} doesn't exists")

            exec_info = BpfLoader2ExecModel.from_data(acct_info.data)

            # Don't try to update EVM config, if we have the same version of the executable account
            if exec_info.deployed_slot == self._evm_cfg.deployed_slot:
                return self._evm_cfg

            _LOG.debug("get EVM config on the slot: %s", exec_info.deployed_slot)
            resp = await self._get_evm_cfg()
            if resp.result != CoreApiResultCode.Success:
                _LOG.error("get error on reading EVM config: %s", resp.error, extra=self._msg_filter)
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
        resp = await self._get_core_build()
        return "Neon-Core-API/v" + resp.crate_info.version + "-" + resp.version_control.commit_id

    async def get_holder_account(self, address: SolPubKey) -> HolderAccountModel:
        req = HolderAccountRequest.from_raw(address)
        resp = await self._get_holder_account(req)
        if resp.error:
            _LOG.error(
                log_msg("error on reading holder account {Address}: {Error}", Address=address, Error=resp.error),
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
        resp = await self._get_neon_account_list(req)
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

    async def get_state_tx_cnt(self, account: NeonAccount, block: NeonBlockHdrModel | None) -> int:
        acct = await self.get_neon_account(account, block)
        return acct.state_tx_cnt

    async def get_neon_contract(self, account: NeonAccount, block: NeonBlockHdrModel | None) -> NeonContractModel:
        req = NeonContractRequest(contract=account.eth_address, slot=self._get_slot(block))
        resp = await self._get_neon_contract(req)
        return NeonContractModel.from_dict(resp.value[0], account=account)

    async def get_storage_at(self, contract: EthAddress, index: int, block: NeonBlockHdrModel | None) -> EthHash32:
        req = NeonStorageAtRequest(contract=contract, index=index, slot=self._get_slot(block))
        resp = await self._get_storage_at(req)
        return EthHash32.from_raw(bytes(resp.value))

    async def emulate(
        self,
        evm_cfg: EvmConfigModel,
        from_address: EthAddressField,
        to_address: EthAddressField,
        value: int,
        data: bytes,
        gas_limit: int | None,
        gas_price: int | None,
        chain_id: int,
        preload_sol_address_list: tuple[SolPubKey, ...],
        sol_account_dict: dict[SolPubKey, SolAccountModel | None],
        check_result: bool,
        block: NeonBlockHdrModel | None,
    ) -> EmulatorResp:
        req = EmulatorRequest(
            tx=EmulatorTxModel(
                from_address=from_address,
                to_address=to_address,
                value=value,
                data=data,
                gas_limit=gas_limit,
                gas_price=gas_price,
                chain_id=chain_id,
            ),
            evm_step_limit=self._cfg.max_emulate_evm_step_cnt,
            token_list=tuple(evm_cfg.token_list),
            preload_sol_address_list=preload_sol_address_list,
            sol_account_dict={addr: EmulatorSolAccount.from_raw(raw) for addr, raw in sol_account_dict.items()},
            slot=self._get_slot(block),
        )
        resp = await self._emulate(req)
        if resp.error:
            raise EthError(resp.error)
        resp = EmulatorResp.from_dict(resp.value)
        if check_result:
            self._check_emulator_result(resp)
        return resp

    async def emulate_tx(
        self,
        evm_cfg: EvmConfigModel,
        neon_tx: NeonTxModel,
        chain_id: int,
        preload_sol_address_list: tuple[SolPubKey, ...],
        sol_account_dict: dict[SolPubKey, SolAccountModel | None],
        check_result: bool,
        block: NeonBlockHdrModel | None,
    ) -> EmulatorResp:
        return await self.emulate(
            evm_cfg,
            neon_tx.from_address,
            neon_tx.to_address,
            neon_tx.value,
            neon_tx.call_data,
            neon_tx.gas_limit,
            neon_tx.gas_price,
            chain_id,
            preload_sol_address_list=preload_sol_address_list,
            sol_account_dict=sol_account_dict,
            check_result=check_result,
            block=block,
        )

    @SimpleAppDataClient.method(name="config")
    async def _get_evm_cfg(self) -> CoreApiResp: ...

    @SimpleAppDataClient.method(name="build-info")
    async def _get_core_build(self) -> CoreApiBuildModel: ...

    @SimpleAppDataClient.method(name="holder")
    async def _get_holder_account(self, request: HolderAccountRequest) -> CoreApiResp: ...

    @SimpleAppDataClient.method(name="balance")
    async def _get_neon_account_list(self, request: NeonAccountListRequest) -> CoreApiResp: ...

    @SimpleAppDataClient.method(name="contract")
    async def _get_neon_contract(self, request: NeonContractRequest) -> CoreApiResp: ...

    @SimpleAppDataClient.method(name="storage")
    async def _get_storage_at(self, request: NeonStorageAtRequest) -> CoreApiResp: ...

    @SimpleAppDataClient.method(name="emulate")
    async def _emulate(self, request: EmulatorRequest) -> CoreApiResp: ...

    @ttl_cached_method(ttl_sec=60)
    async def _get_evm_exec_addr(self) -> SolPubKey:
        # Load the BPF program account to get the address of the BPF executable account
        acct = await self._sol_client.get_account(NeonProg.ID)
        if acct.is_empty:
            raise ValueError(f"Account {NeonProg.ID} doesn't exists")

        prog = BpfLoader2ProgModel.from_data(acct.data)
        return prog.exec_address

    def _check_emulator_result(self, resp: EmulatorResp) -> None:
        if resp.exit_code == EmulatorExitCode.Revert:
            revert_data = resp.result.to_string()[2:]
            _LOG.debug("got reverted result with data: %s", revert_data)
            result_value = self._decode_revert_message(revert_data)
            if not result_value:
                raise EthError(code=3, message="execution reverted", data="0x" + revert_data)
            else:
                raise EthError(code=3, message="execution reverted: " + result_value, data="0x" + revert_data)

        if resp.exit_code != EmulatorExitCode.Succeed:
            _LOG.debug("got failed emulate exit code: %s", resp.exit_code)
            raise EthError(code=3, message=resp.exit_code)

    @staticmethod
    def _decode_revert_message(data: str) -> str | None:
        if not data:
            return None

        data_len = len(data)
        if data_len < 8:
            raise EthError(code=3, message=f"Too less bytes to decode revert signature: {data_len}", data=data)

        if data[:8] == "4e487b71":  # keccak256("Panic(uint256)")
            return None

        if data[:8] != "08c379a0":  # keccak256("Error(string)")
            _LOG.debug(f"failed to decode revert_message, unknown revert signature: {data[:8]}")
            return None

        if data_len < 8 + 64:
            raise EthError(code=3, message=f"Too less bytes to decode revert msg offset: {data_len}", data=data)
        offset = int(data[8 : 8 + 64], 16) * 2

        if data_len < 8 + offset + 64:
            raise EthError(code=3, message=f"Too less bytes to decode revert msg len: {data_len}", data=data)
        length = int(data[8 + offset : 8 + offset + 64], 16) * 2

        if data_len < 8 + offset + 64 + length:
            raise EthError(code=3, message=f"Too less bytes to decode revert msg: {data_len}", data=data)

        message = str(bytes.fromhex(data[8 + offset + 64 : 8 + offset + 64 + length]), "utf8")
        return message

    def _get_slot(self, block: NeonBlockHdrModel | None) -> int | None:
        if block:
            if block.commit in (EthCommit.Latest, EthCommit.Pending):
                return None
            elif self._cfg.ch_dsn_list:
                return block.slot
        return None

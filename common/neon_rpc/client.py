from __future__ import annotations

import itertools
import logging
from typing import List, Sequence, Final, TypeVar, ClassVar, Union

from .api import (
    EvmConfigModel,
    BpfLoader2ExecModel,
    BpfLoader2ProgModel,
    CoreApiBuildModel,
    HolderAccountModel,
    NeonAccountModel,
    HolderAccountRequest,
    NeonAccountListRequest,
    EmulNeonCallResp,
    EmulNeonCallRequest,
    EmulMultipleNeonCallRequest,
    EmulMultipleNeonCallResp,
    CoreApiTxModel,
    EmulNeonCallExitCode,
    NeonStorageAtRequest,
    NeonContractRequest,
    NeonContractModel,
    EmulSolAccountModel,
    EmulSolTxListResp,
    EmulSolTxListRequest,
    EmulSolTxMetaModel,
    OpEarnAccountModel,
    NeonAccountStatus,
    EmulTraceCfgModel,
    EmulNeonAccountModel,
    CoreApiBlockModel,
    NeonSkdTreeModel,
    NeonSkdTreeRequest,
    TokenModel,
)
from ..jsonrpc.client import JsonRpcClient
from ..config.config import Config
from ..config.constants import ONE_BLOCK_SEC
from ..ethereum import revert_message
from ..ethereum.commit_level import EthCommit
from ..ethereum.errors import EthError
from ..ethereum.hash import EthAddress, EthHash32
from ..http.client import HttpClient, HttpClientRequest
from ..http.utils import HttpURL
from ..neon.address import NeonAddress
from ..neon.block import NeonBlockHdrModel
from ..neon.neon_program import NeonProg
from ..solana.account import SolAccountModel
from ..solana.cb_program import SolCbProg
from ..solana.errors import SolAltError
from ..solana.hash import SolBlockHash
from ..solana.pubkey import SolPubKey
from ..solana.transaction import SolTx
from ..solana_rpc.client import SolClient
from ..utils.cached import cached_method
from ..utils.pydantic import BaseModel, RootModel, HexUIntField
from proxy.stat.client import StatClient

_LOG = logging.getLogger(__name__)
_RespType = TypeVar("_RespType", bound=Union[BaseModel, RootModel])

class CoreRpcClient(JsonRpcClient):
    name: ClassVar[str] = "CoreRpcClient"
    _wait_sec: Final[float] = max(ONE_BLOCK_SEC / 5, 0.05)

    def __init__(self, cfg: Config, sol_client: SolClient, stat_client: StatClient) -> None:
        super().__init__(cfg, stat_client)

        for idx in range(cfg.neon_core_api_server_cnt):
            port = cfg.neon_core_api_port + idx
            self.connect(host=cfg.neon_core_api_ip, port=port)

        self.set_timeout_sec(120).set_max_retry_cnt(30)
        self._sol_client = sol_client
        self._deployed_slot = -1
        self._token_list_cache: list[TokenModel] = list()

    async def get_evm_cfg(self) -> EvmConfigModel | None:
        try:
            # Load the BPF program account to get the address of the BPF executable account
            exec_addr = await self._get_evm_exec_addr()

            # Load the header of the executable account to get the deployed slot
            min_size = BpfLoader2ExecModel.minimum_size
            acct = await self._sol_client.get_account(exec_addr, min_size)
            if acct.is_empty:
                _LOG.error("NeonEVM program %s doesn't exists", exec_addr)
                return None
            exec_info = BpfLoader2ExecModel.from_data(acct.data)

            # Load EVM config and return it with deployed slot
            resp = await self._get_config()
            model = EvmConfigModel.from_dict(resp.to_dict(), deployed_slot=exec_info.deployed_slot)
            return model
        except BaseException as exc:
            _LOG.error("error on reading EVM config", exc_info=exc)
            return None

    @cached_method
    async def get_core_api_version(self) -> str:
        try:
            resp = await self._get_build_info()
            return "Neon-Core-API/v" + resp.crate_info.version + "-" + resp.version_control.commit_id
        except BaseException as exc:
            _LOG.error("error on reading EVM build info", exc_info=exc)
            return "Neon-Core-API/UNKNOWN"

    async def get_holder_account(self, address: SolPubKey) -> HolderAccountModel:
        try:
            req = HolderAccountRequest.from_raw(address)
            resp = await self._get_holder(req)
            return HolderAccountModel.from_cls(resp, address, NeonProg.DefaultChainId)
        except BaseException as exc:
            _LOG.error("error on reading holder account", exc_info=exc)
            return HolderAccountModel.new_empty(address)

    async def get_neon_account_list(
            self,
            address_list: Sequence[NeonAddress],
            block: NeonBlockHdrModel | None,
    ) -> Sequence[NeonAccountModel]:
        try:
            req = NeonAccountListRequest.from_raw(address_list, self._get_slot(block))
            resp = await self._get_balance(req)
            return tuple([NeonAccountModel.from_cls(data, addr) for addr, data in zip(address_list, resp)])
        except BaseException as exc:
            _LOG.error("error on reading Neon account list", exc_info=exc)
            return tuple([NeonAccountModel.new_empty(addr) for addr in address_list])

    async def get_neon_account(self, address: NeonAddress, block: NeonBlockHdrModel | None) -> NeonAccountModel:
        acct_list = await self.get_neon_account_list([address], block)
        return acct_list[0]

    async def get_state_tx_cnt(self, address: NeonAddress, block: NeonBlockHdrModel | None = None) -> int:
        acct = await self.get_neon_account(address, block)
        return acct.state_tx_cnt

    async def get_neon_contract(self, address: NeonAddress, block: NeonBlockHdrModel | None) -> NeonContractModel:
        req = NeonContractRequest(contract=address.eth_address, slot=self._get_slot(block))
        resp = await self._get_contract(req)
        return NeonContractModel(neon_address=address, code=resp[0].code, sol_address=resp[0].sol_address)

    async def get_storage_at(self, contract: EthAddress, index: int, block: NeonBlockHdrModel | None) -> EthHash32:
        req = NeonStorageAtRequest(contract=contract, index=index, slot=self._get_slot(block))
        resp = await self._get_storage_at(req)
        return EthHash32.from_raw(bytes(resp))

    async def get_neon_skd_tree(
        self,
        payer: NeonAddress,
        nonce: int,
        block: NeonBlockHdrModel | None = None,
    ) -> NeonSkdTreeModel:
        req = NeonSkdTreeRequest.from_raw(payer=payer, nonce=nonce, slot=self._get_slot(block))
        return await self._get_transaction_tree(req)

    async def get_earn_account(
        self,
        operator_key: SolPubKey,
        address: NeonAddress,
        _block: NeonBlockHdrModel | None,
    ) -> OpEarnAccountModel:
        seed_list = (
            NeonProg.AccountSeedVersion.to_bytes(1, byteorder="little"),
            operator_key.to_bytes(),
            address.eth_address.to_bytes(),
            address.chain_id.to_bytes(32, byteorder="big"),
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
            neon_address=address,
            token_sol_address=token_sol_addr,
            balance=balance,
        )

    async def emulate_neon_call(
        self,
        tx: CoreApiTxModel,
        *,
        check_result: bool,
        sender_balance: int | None = None,
        preload_sol_address_list: Sequence[SolPubKey] = tuple(),
        sol_account_dict: dict[SolPubKey, SolAccountModel | None] | None = None,
        emulator_block=CoreApiBlockModel.default(),
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
            if emul_balance:
                _LOG.debug("use predefined balance: %s", emul_balance)
            emul_neon_acct_dict[tx.from_address] = EmulNeonAccountModel(nonce=tx.nonce, balance=emul_balance)

        emul_trace_cfg = None
        if emul_neon_acct_dict or emulator_block:
            emul_trace_cfg = EmulTraceCfgModel(neon_account_dict=emul_neon_acct_dict, block=emulator_block)

        preload_sol_address_list = list(preload_sol_address_list)

        for retry in itertools.count():
            req = EmulNeonCallRequest(
                tx=tx,
                evm_step_limit=self._cfg.max_emulate_evm_step_cnt,
                evm_account_limit=self._cfg.max_tx_account_cnt - NeonProg.BaseAccountCnt,
                token_list=self._token_list,
                trace_cfg=emul_trace_cfg,
                preload_sol_address_list=preload_sol_address_list,
                sol_account_dict=emul_sol_acct_dict,
                slot=self._get_slot(block),
            )
            resp = await self._emulate(req)
            if (not retry) and (not preload_sol_address_list) and self._cfg.reemulate_on_full_account_list:
                preload_sol_address_list = resp.sol_address_list
                continue

            try:
                self._check_emulator_result(resp)
            except EthError:
                if not retry:
                    preload_sol_address_list = resp.sol_address_list
                    continue
                elif check_result:
                    raise

            return resp
        assert False, "unreached code"


    async def emulate_multiple_neon_call(
        self,
        sol_tx_list: Sequence[SolTx],
        neon_tx_list: Sequence[CoreApiTxModel],
        *,
        cu_limit=SolCbProg.MaxCuLimit,
        heap_size=SolCbProg.MaxHeapSize,
        account_cnt_limit=0,
        check_result: bool,
        preload_sol_address_list: Sequence[SolPubKey] = tuple(),
        block: NeonBlockHdrModel | None = None,
    ) -> Sequence[EmulNeonCallResp]:
        preload_sol_address_list = list(preload_sol_address_list)
        neon_tx_list = list(neon_tx_list)
        _RootType = EmulMultipleNeonCallResp

        def _get_full_preload_addr_list(_resp: _RootType) -> list[SolPubKey]:
            return list(set(itertools.chain.from_iterable(x.sol_address_list for x in _resp.root)))

        blockhash = SolBlockHash.fake()
        for sol_tx in sol_tx_list:
            sol_tx.set_recent_blockhash(blockhash)

        sol_tx_req = EmulSolTxListRequest(
            cu_limit=cu_limit,
            heap_size=heap_size,
            account_cnt_limit=account_cnt_limit or self._cfg.max_tx_account_cnt,
            verify=False,
            blockhash=blockhash.to_bytes(),
            tx_list=list(map(lambda tx: tx.to_bytes(), sol_tx_list)),
        )

        for retry in itertools.count():
            req = EmulMultipleNeonCallRequest(
                sol_tx_request=sol_tx_req,
                neon_tx_list=neon_tx_list,
                evm_step_limit=self._cfg.max_emulate_evm_step_cnt,
                evm_account_limit=self._cfg.max_tx_account_cnt - NeonProg.BaseAccountCnt,
                token_list=self._token_list,
                preload_sol_address_list=preload_sol_address_list,
                slot=self._get_slot(block),
            )
            resp = await self._emulate_multiple(req)
            if (not retry) and (not preload_sol_address_list) and self._cfg.reemulate_on_full_account_list:
                preload_sol_address_list = _get_full_preload_addr_list(resp)
                continue

            try:
                for r in resp.root:
                    self._check_emulator_result(r)
            except EthError:
                if not retry:
                    preload_sol_address_list = _get_full_preload_addr_list(resp)
                    continue
                elif check_result:
                    raise
            return resp.root
        assert False, "unreached code"


    async def emulate_sol_tx_list(
        self,
        cu_limit: int,
        heap_size: int,
        account_cnt_limit: int,
        blockhash: SolBlockHash,
        tx_list: Sequence[SolTx],
    ) -> Sequence[EmulSolTxMetaModel]:
        req = EmulSolTxListRequest(
            cu_limit=cu_limit,
            heap_size=heap_size,
            account_cnt_limit=account_cnt_limit,
            verify=False,
            blockhash=blockhash.to_bytes(),
            tx_list=list(map(lambda tx: tx.to_bytes(), tx_list)),
        )
        resp: EmulSolTxListResp = await self._simulate_solana(req)
        return tuple(resp.meta_list)

    @JsonRpcClient.method(name="build_info")
    async def _get_build_info(self) -> CoreApiBuildModel: ...

    @JsonRpcClient.method(name="config")
    async def _get_config(self) -> EvmConfigModel: ...

    @JsonRpcClient.method(name="balance")
    async def _get_balance(self, req: NeonAccountListRequest) -> Sequence[NeonAccountModel]: ...

    @JsonRpcClient.method(name="contract")
    async def _get_contract(self, req: NeonContractRequest) -> Sequence[NeonContractModel]: ...

    @JsonRpcClient.method(name="holder")
    async def _get_holder(self, req: HolderAccountRequest) -> HolderAccountModel: ...

    @JsonRpcClient.method(name="get_storage_at")
    async def _get_storage_at(self, req: NeonStorageAtRequest) -> Sequence[HexUIntField]: ...

    @JsonRpcClient.method(name="transaction_tree")
    async def _get_transaction_tree(self, req: NeonSkdTreeRequest) -> NeonSkdTreeModel: ...

    @JsonRpcClient.method(name="emulate")
    async def _emulate(self, req: EmulNeonCallRequest) -> EmulNeonCallResp: ...

    @JsonRpcClient.method(name="emulate_multiple")
    async def _emulate_multiple(self, req: EmulMultipleNeonCallRequest) -> EmulMultipleNeonCallResp: ...

    @JsonRpcClient.method(name="simulate_solana")
    async def _simulate_solana(self, req: EmulSolTxListRequest) -> EmulSolTxListResp: ...

    async def _get_evm_exec_addr(self) -> SolPubKey:
        # Load the BPF program account to get the address of the BPF executable account
        acct = await self._sol_client.get_account(NeonProg.ID)
        if acct.is_empty:
            raise ValueError(f"Account {NeonProg.ID} doesn't exists")

        prog = BpfLoader2ProgModel.from_data(acct.data)
        return prog.exec_address

    def _exception_handler(self, url: HttpURL, request: HttpClientRequest, retry: int, exc: BaseException) -> None:
        super()._exception_handler(url, request, retry, exc)

        # if the previous call has re-raised an exception, this code isn't called
        # assert isinstance(request, HttpClientRequest)
        # request.commit_stat(error_message=str(exc) or "Unknown", start_timer=True)
        _LOG.warning("bad neon-core-api response on request %s: %s", request.data, str(exc), extra=self._msg_filter)

    @staticmethod
    def _rpc_error_handler(method: str, code: int, message: str, error_list: Sequence[str] | None) -> str | None:
        if code == 113:  # ClientError, Solana connection problem
            return f"Solana connection error on {method}"
        elif code != 265:  # SolanaSimulatorError
            return None

        sim_error: Final[str] = "Solana Simulator error "
        sim_error_len: Final[int] = len(sim_error)
        rpc_error: Final[str] = "RpcClientError"  # Solana connection problem
        tx_error: Final[str] = "TransactionError"  # Transaction body problem
        tx_error_len: Final[int] = len(tx_error)

        error = message[sim_error_len:]
        if error.startswith(rpc_error):
            return f"Solana connection error on {method}"
        elif not error.startswith(tx_error):
            return None

        sub_error = error[tx_error_len:]
        alt_error_list: Final[tuple] = (
            "(AddressLookupTableNotFound)",
            "(InvalidAddressLookupTableOwner)",
            "(InvalidAddressLookupTableData)",
            "(InvalidAddressLookupTableIndex)",
        )
        for alt_error in alt_error_list:
            if sub_error.startswith(alt_error):
                raise SolAltError("Simulation error: " + alt_error)

        return None

    @staticmethod
    def _check_emulator_result(resp: EmulNeonCallResp) -> None:
        if resp.exit_code == EmulNeonCallExitCode.Revert:
            revert_data = resp.result.to_string()
            # _LOG.debug("got reverted result with data: %s", revert_data)

            if not (result_value := revert_message.decode(revert_data[2:])):  # remove 0x
                raise EthError(code=3, message="execution reverted", data=revert_data)
            else:
                raise EthError(
                    code=3,
                    message="execution reverted: " + result_value,
                    data=revert_data,
                )

        if resp.exit_code != EmulNeonCallExitCode.Succeed:
            raise EthError(code=3, message=resp.exit_code)

    def _get_slot(self, block: NeonBlockHdrModel | None) -> int | None:
        if block:
            if block.commit in (EthCommit.Latest, EthCommit.Pending):
                return None
            elif self._cfg.ch_dsn_list:
                return block.slot
        return None

    @property
    def _token_list(self) -> list[TokenModel]:
        if self._deployed_slot != NeonProg.DeployedSlot:
            self._deployed_slot = NeonProg.DeployedSlot
            self._token_list_cache = [TokenModel.from_raw(token) for token in NeonProg.TokenList]
        return self._token_list_cache



class CoreApiClient(CoreRpcClient):
    name: ClassVar[str] = "CoreApiClient"
    pass

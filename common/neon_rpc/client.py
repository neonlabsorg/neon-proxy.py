from __future__ import annotations

import unittest
import asyncio
import itertools
import logging
import pprint
import uuid
from typing import List, Sequence, Final, TypeVar, ClassVar, Union
from pydantic import StrictInt, StrictStr, AliasChoices, Field, ConfigDict, Base64Bytes

from common.neon_rpc.api import (
    CoreApiResp,
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
    CoreApiRequest,
    TokenModel,
)
from common.jsonrpc.client import JsonRpcClient
from common.config.config import Config
from common.config.constants import ONE_BLOCK_SEC
from common.ethereum import revert_message
from common.ethereum.commit_level import EthCommit
from common.ethereum.errors import EthError
from common.ethereum.hash import EthAddress, EthHash32
from common.http.client import HttpClient, HttpClientRequest
from common.http.errors import PydanticValidationError
from common.http.utils import HttpURL
from common.neon.address import NeonAddress
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonProg
from common.solana.account import SolAccountModel
from common.solana.cb_program import SolCbProg
from common.solana.errors import SolAltError
from common.solana.hash import SolBlockHash
from common.solana.pubkey import SolPubKey
from common.solana.transaction import SolTx
from common.solana_rpc.client import SolClient
from common.stat.client_rpc import RpcStatClient, RpcClientRequest
from common.utils.cached import cached_method
from common.utils.format import if_none
from common.utils.json_logger import log_msg
from common.utils.pydantic import BaseModel, RootModel, HexUIntField
from proxy.stat.client import StatClient

_LOG = logging.getLogger(__name__)
_RespType = TypeVar("_RespType", bound=Union[BaseModel, RootModel])

"""
class CoreRpcRequest(BaseModel):
    @staticmethod
    def _gen_unique_id() -> str:
        value = str(uuid.uuid4())
        _LOG.debug("generate ID %s for core-api", value)
        return value
    ctx_id: str = Field(serialization_alias="id", default_factory=_gen_unique_id)

class CoreApiResponse(BaseModel):
    _model_config = BaseModel.model_config.copy()
    _model_config.pop("extra")

    model_config = ConfigDict(
        extra="allow",
        **_model_config,
    )

class GetBalanceRequest(CoreApiRequest):
    class Address(BaseModel):
        address: str
        chain_id: int
    account: List[Address]
    slot: int | None = None

class GetBalanceResponse(CoreApiResponse):
    #class Address(BaseModel):
    #    solana_address: str
    #    contract_solana_address: str
    #    trx_count: int
    #    balance: str
    #    status: str
    #    user_pubkey: str
    pass

class GetContractRequest(CoreApiRequest):
    contract: str
    slot: int | None = None
    pass

class GetContractResponse(CoreApiResponse):
    pass

class GetHolderRequest(CoreApiRequest):
    pubkey: str
    pass

class GetHolderResponse(CoreApiResponse):
    pass

class GetStorageRequest(CoreApiRequest):
    contract: str
    index: HexUIntField
    slot: int | None = None

class GetStorageResponse(RootModel):
    root: List[int]

class GetTransactionTreeRequest(CoreApiRequest):
    class Address(BaseModel):
        address: str
        chain_id: int
    origin: Address
    nonce: int
    slot: int | None = None

class GetTransactionTreeResponse(CoreApiResponse):
    class TxNode(CoreApiResponse):
        status: str
        result_hash: str
        transaction_hash: str
        gas_limit: HexUIntField
        value: HexUIntField
        child_transaction: int
        success_execute_limit: int
        parent_count: int
    status: str
    pubkey: str
    payer: str
    last_slot: int
    chain_id: int
    max_fee_per_gas: HexUIntField
    max_priority_fee_per_gas: HexUIntField
    balance: HexUIntField
    last_index: int
    transactions: List[TxNode]

class EmulateNeonCallRequest(CoreApiRequest):
    pass

class EmulateNeonCallResponse(CoreApiResponse):
    pass

class EmulateMultNeonCallRequest(CoreApiRequest):
    pass

class EmulateMultNeonCallResponse(CoreApiResponse):
    pass

class EmulateRequest(CoreApiRequest):
    pass

class EmulateResponse(CoreApiResponse):
    pass

class EmulateMultipleRequest(CoreApiRequest):
    pass

class EmulateMultipleResponse(CoreApiResponse):
    pass

class SimulateSolanaRequest(CoreApiRequest):
    compute_units: int
    heap_size: int
    account_limit: int
    verify: bool
    blockhash: str
    transactions: List[str]

class SimulateSolanaResponse(CoreApiResponse):
    pass
"""

class CoreRpcClient(JsonRpcClient):
    def __init__(self, cfg: Config, sol_client: SolClient, stat_client: StatClient) -> None:
        super().__init__(cfg)

        for idx in range(cfg.neon_core_api_server_cnt):
            port = cfg.neon_core_api_port + idx
            self.connect(host=cfg.neon_core_api_ip, port=port)

        self.set_timeout_sec(120).set_max_retry_cnt(30)
        self._stat_client = stat_client
        self._sol_client = sol_client
        self._deployed_slot = -1

    async def get_core_api_version(self) -> str:
        try:
            resp = await self._get_build_info()
            return "Neon-Core-API/v" + resp.crate_info.version + "-" + resp.version_control.commit_id
        except BaseException as exc:
            _LOG.error("error on reading EVM build info", exc_info=exc)
            return "Neon-Core-API/UNKNOWN"

    async def get_evm_cfg(self) -> EvmConfigModel | None:
        try:
            # Load the BPF program account to get the address of the BPF executable account
            acct = await self._sol_client.get_account(NeonProg.ID)
            if acct.is_empty:
                raise ValueError(f"Account {NeonProg.ID} doesn't exists")
            prog = BpfLoader2ProgModel.from_data(acct.data)

            # Load the header of the executable account to get the deployed slot
            min_size = BpfLoader2ExecModel.minimum_size
            acct = await self._sol_client.get_account(prog.exec_address, min_size)
            if acct.is_empty:
                _LOG.error("NeonEVM program %s doesn't exists", prog.exec_addr)
                return None
            exec_info = BpfLoader2ExecModel.from_data(acct.data)

            # Load EVM config and return it with deployed slot
            resp = await self._get_config()
            model = EvmConfigModel.from_dict(resp.to_dict(), deployed_slot=exec_info.deployed_slot)
            return model
        except BaseException as exc:
            _LOG.error("error on reading EVM config", exc_info=exc)
            return None

    async def get_holder_account(self, address: SolPubKey) -> HolderAccountModel:
        try:
            req = HolderAccountRequest.from_raw(address)
            resp = await self._get_holder(req)
            return HolderAccountModel.from_addr(address,
                                                NeonProg.DefaultChainId,
                                                {
                                                    "status": resp.status,
                                                    "len": resp.size,
                                                    "owner": resp.owner,
                                                    "tx": resp.neon_tx_hash,
                                                    "tx_type": resp.tx_type,
                                                    "steps_executed": resp.evm_step_cnt
                                                })
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
            return tuple([NeonAccountModel(sol_address=data.sol_address,
                                           contract_sol_address=data.contract_sol_address,
                                           state_tx_cnt=data.state_tx_cnt,
                                           balance=data.balance,
                                           status=data.status,
                                           user_sol_address=data.user_sol_address,
                                           neon_address=a)
                          for a, data in zip(address_list, resp)])
        except BaseException as exc:
            _LOG.error("error on reading Neon account list", exc_info=exc)
            return tuple([NeonAccountModel.new_empty(addr) for addr in address_list])

    """
    async def get_neon_account_list(
            self,
            address_list: Sequence[NeonAddress],
            block: NeonBlockHdrModel | None,
    ) -> Sequence[NeonAccountModel]:
        try:
            srl_addr_list = []
            for addr in address_list:
                srl_addr_list.append({"address": addr.to_address(), "chain_id": addr.chain_id})
            req = GetBalanceRequest.from_dict({"account": srl_addr_list, "slot": self._get_slot(block)})
            resp = await self._get_balance(req)
            return tuple([NeonAccountModel.from_dict(r.to_dict(), address=a) for a, r in zip(address_list, resp)])
        except BaseException as exc:
            _LOG.error("error on reading Neon account list", exc_info=exc)
            return tuple([NeonAccountModel.new_empty(addr) for addr in address_list])
    """

    async def get_neon_account(self, address: NeonAddress, block: NeonBlockHdrModel | None) -> NeonAccountModel:
        acct_list = await self.get_neon_account_list([address], block)
        return acct_list[0]

    async def get_state_tx_cnt(self, address: NeonAddress, block: NeonBlockHdrModel | None = None) -> int:
        acct = await self.get_neon_account(address, block)
        return acct.state_tx_cnt

    async def get_neon_contract(self, address: NeonAddress, block: NeonBlockHdrModel | None) -> NeonContractModel:
        req = NeonContractRequest(contract=address.eth_address, slot=self._get_slot(block))
        resp = await self._get_contract(req)
        return NeonContractModel(neon_address=address, code=resp[0].code, solana_address=resp[0].sol_address)

    async def get_storage_at(self, contract: EthAddress, index: int, block: NeonBlockHdrModel | None) -> EthHash32:
        req = NeonStorageAtRequest(contract=contract, index=index, slot=self._get_slot(block))
        resp = await self._get_storage_at(req)
        #pprint.pp(["___", resp, "___"])
        return EthHash32.from_raw(bytes(resp))
        #req = GetStorageRequest.from_dict({
        #    "contract": contract.to_string(),
        #    "index": index,
        #    "slot": self._get_slot(block)
        #})
        #resp = await self._get_storage_at(req)
        #return EthHash32.from_raw(bytes(resp.to_dict()))

    async def get_neon_skd_tree(
        self,
        payer: NeonAddress,
        nonce: int,
        block: NeonBlockHdrModel | None = None,
    ) -> NeonSkdTreeModel:
        req = NeonSkdTreeRequest.from_raw(payer=payer, nonce=nonce, slot=self._get_slot(block))
        return await self._get_transaction_tree(req)
        #pprint.pp(resp.to_dict())
        #return NeonSkdTreeModel.from_dict(resp.to_dict())

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

    #@JsonRpcClient.method(name="balance")
    #async def _get_balance(self, req: GetBalanceRequest) -> List[GetBalanceResponse]: ...

    @JsonRpcClient.method(name="balance")
    async def _get_balance(self, req: NeonAccountListRequest) -> Sequence[NeonAccountModel]: ...

    #@JsonRpcClient.method(name="contract")
    #async def _get_contract(self, req: GetContractRequest) -> List[GetContractResponse]: ...

    @JsonRpcClient.method(name="contract")
    async def _get_contract(self, req: NeonContractRequest) -> Sequence[NeonContractModel]: ...

    @JsonRpcClient.method(name="holder")
    async def _get_holder(self, req: HolderAccountRequest) -> HolderAccountModel: ...

    #@JsonRpcClient.method(name="get_storage_at")
    #async def _get_storage_at(self, req: GetStorageRequest) -> GetStorageResponse: ...

    @JsonRpcClient.method(name="get_storage_at")
    async def _get_storage_at(self, req: NeonStorageAtRequest) -> Sequence[HexUIntField]: ...

    #@JsonRpcClient.method(name="transaction_tree")
    #async def _get_transaction_tree(self, req: GetTransactionTreeRequest) -> GetTransactionTreeResponse: ...

    @JsonRpcClient.method(name="transaction_tree")
    async def _get_transaction_tree(self, req: NeonSkdTreeRequest) -> NeonSkdTreeModel: ...

    @JsonRpcClient.method(name="emulate")
    async def _emulate(self, req: EmulNeonCallRequest) -> EmulNeonCallResp: ...

    @JsonRpcClient.method(name="emulate_multiple")
    async def _emulate_multiple(self, req: EmulMultipleNeonCallRequest) -> EmulMultipleNeonCallResp: ...

    @JsonRpcClient.method(name="simulate_solana")
    async def _simulate_solana(self, req: EmulSolTxListRequest) -> EmulSolTxListResp: ...

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
            # _LOG.debug("got failed emulate exit code: %s", resp.exit_code)
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
    pass



class TestCoreRpcClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config = Config()
        self._stat_client = StatClient(config)
        self._sol_client = SolClient(config, self._stat_client)
        self._rpc_client = CoreRpcClient(config,
                                         self._sol_client,
                                         self._stat_client).connect(host="127.0.0.1", port=9104)
        self._api_client = CoreApiClient(config,self._sol_client, self._stat_client)
        await self._stat_client.start()
        await self._sol_client.start()

    async def asyncTearDown(self):
        await self._api_client.stop()
        await self._rpc_client.stop()
        await self._sol_client.stop()
        await self._stat_client.stop()

    @unittest.skip
    async def test_core_api_version(self):
        resp = await self._rpc_client.get_core_api_version()
        pprint.pp(resp)

    @unittest.skip
    async def test_evm_cfg(self):
        resp = await self._rpc_client.get_evm_cfg()
        pprint.pp(resp.to_dict())

    @unittest.skip
    async def test_holder_account(self):
        address = SolPubKey.from_string("2f372pRn7EMdw5zXg777AJT35KdjLSssFN5WF4tEwxLf")
        resp = await self._api_client.get_holder_account(address)
        pprint.pp(resp.to_dict())

    @unittest.skip
    async def test_neon_account_list(self):
        address_list = [
            NeonAddress.from_raw("0x5860522454aa6bF2c4a09D301e004cd334038Ff8", 114),
            NeonAddress.from_raw("0x5860522454aa6bF2c4a09D301e004cd334038Ff8", 114)
        ]
        resp = await self._rpc_client.get_neon_account_list(address_list, NeonBlockHdrModel.default())
        for acc in resp:
            pprint.pp(acc.to_dict())
        pprint.pp(NeonAccountModel.new_empty(address_list[0]).to_dict())
        pass

    @unittest.skip
    async def test_neon_contract(self):
        address = NeonAddress.from_raw("0x5860522454aa6bF2c4a09D301e004cd334038Ff8", 114)
        resp = await self._rpc_client.get_neon_contract(address, NeonBlockHdrModel.default())
        pprint.pp(resp.to_dict())

    #@unittest.skip
    async def test_storage_at(self):
        contract = EthAddress.from_raw("0x3e44a5098621C0B7E1B76edBF8Da18252d74D360")
        resp = await self._rpc_client.get_storage_at(contract, 1, NeonBlockHdrModel.default())
        pprint.pp(resp)

    @unittest.skip
    async def test_neon_skd_tree(self):
        payer = NeonAddress.from_raw("0x43d06925D5B01fe1ABFCb13DB0F3a706106A8e03", 112)
        resp = await self._rpc_client.get_neon_skd_tree(payer, 0, NeonBlockHdrModel.default())
        #pprint.pp(resp.to_dict())

    @unittest.skip
    async def test_simulate_solana(self):
        req = EmulSolTxListRequest.from_dict({
            "account_cnt_limit": 255,
            "blockhash": "0691a8386ec771ec9914c7a0a26d67ca2bb04f22cc1a42c5d110c0d2027ed604",
            "cu_limit": 1400000,
            "heap_size": 262144,
            "tx_list": ["018c4cda5240ea6c1e0e1e8f969aca87497484700b7b71cb93d2452f17a31f9c1ddadb9c4eaf92f32e03e5dc26c4b094f666e5ede1986a4a1fc96f4ac9ffcbbb0e0100030a7bf08608a676d074e5232735cbce615f166bec3e46c8bf3fdd229a5b9f99b4ab19df5a324e77a9f550a53a8a024cd268eb8df44c885175cd4e3a51558df1b82239c2350b7d1034884000b2b96e9482484cf6fc9a5cea7e92861702af2685872b46ff27d03dd553c765b1d2cb2ae16172a989eacb90b292edba8540105970f8b16e14438ed9206aa8b1d1c56f0a3334c897cb1200d09f5c04ec4bd0f4ed754cc5948363f8f2ae302c947d301c055f268285526121c9c7b8cbfa58def895f73fa4c24beca9b9e4482b5a124f178d944a64417a65bb36cab34117cbb8b6fd700da700000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000003c00392b787d38a853d124057634c43c7133c612461d74feb17f4248155286c00691a8386ec771ec9914c7a0a26d67ca2bb04f22cc1a42c5d110c0d2027ed6040408000903042900000000000008000502c05c150008000501000004000908020005060701030493043d76000000f9020b0f849c76524184013ad9ef8080b901b6608060405234801561001057600080fd5b50610196806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639c4ae2d014610030575b600080fd5b61004361003e3660046100ab565b610045565b005b6000818351602085016000f56040516001600160a01b03821681529091507f55ea6c6b31543d8e2ec6a72f71a79c0f4b72ed0d4757172b043d8f4f4cd848489060200160405180910390a1505050565b634e487b7160e01b600052604160045260246000fd5b600080604083850312156100be57600080fd5b823567ffffffffffffffff808211156100d657600080fd5b818501915085601f8301126100ea57600080fd5b8135818111156100fc576100fc610095565b604051601f8201601f19908116603f0116810190838211818310171561012457610124610095565b8160405282815288602084870101111561013d57600080fd5b82602086016020830137600060209382018401529896909101359650505050505056fea264697066735822122029400b0d7e26fec77a532d21ada2fda50b813bcf63f041e8ba162d16e10ea56964736f6c634300080a0033820102a09d87d70c6c4704228ee49506eab0d11ddf21005978bdcdfc3b86f5007ea2c6b4a0355f4d0b7d38b972c1b8afa2d0085d4cf669f3dbe106eb33eea350dac5db2b9c"],
            "verify": False
        })
        resp = await self._rpc_client._simulate_solana(req)
        pprint.pp(resp.meta_list[0].to_dict())

if __name__ == "__main__":
    unittest.main()
#
#

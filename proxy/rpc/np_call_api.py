from __future__ import annotations

import asyncio
from typing import ClassVar, Any, Final, Sequence

from pydantic import Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthWrongChainIdError, EthError
from common.ethereum.hash import EthAddressField, EthHash32Field
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.jsonrpc.errors import InvalidParamError
from common.neon.address import NeonAddress
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonProg
from common.neon.skd_tree import NeonSkdTreeAddress
from common.neon.transaction_model import NeonTxModel, NeonTxType
from common.neon_rpc.api import EmulAccountMetaModel, EmulNeonCallResp, CoreApiTxModel
from common.solana.instruction import SolTxIx, SolAccountMeta
from common.solana.pubkey import SolPubKeyField, SolPubKey
from common.solana.sys_program import SolSysProg
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.utils.cached import cached_property, cached_method
from common.utils.format import if_none
from common.utils.pydantic import HexUIntField, RootModel, Base58Field
from .api import RpcBlockRequest, RpcNeonCallRequest
from .server_abc import NeonProxyApi
from ..base.rpc_api import RpcEthTxRequest, BaseEthGasModel, BaseEthCallModel
from ..base.rpc_gas_limit_calculator import RpcNeonGasLimitCalculator


class _RpcEthAccountModel(BaseJsonRpcModel):
    nonce: HexUIntField = Field(0)
    code: EthBinStrField = Field(bytes())
    balance: HexUIntField = Field(0)
    state: dict[EthHash32Field, EthHash32Field] = Field(default_factory=dict)
    stateDiff: dict[EthHash32Field, EthHash32Field] = Field(default_factory=dict)


class _RpcEthStateRequest(RootModel):
    root: dict[EthAddressField, _RpcEthAccountModel] = Field(default_factory=dict)

    _default: ClassVar[_RpcEthStateRequest | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(root=dict())
        return cls._default


class _RpcSolanaAccountModel(BaseJsonRpcModel):
    pubkey: SolPubKeyField
    isWritable: bool
    isLegacy: bool

    @classmethod
    def from_raw(cls, raw: _RpcSolanaAccountModel | EmulAccountMetaModel | None) -> Self | None:
        if raw is None:
            return None
        elif isinstance(raw, _RpcSolanaAccountModel):
            return raw
        elif isinstance(raw, EmulAccountMetaModel):
            return cls(pubkey=raw.pubkey, isWritable=raw.is_writable, isLegacy=raw.is_legacy)
        raise ValueError(f"Wrong input type: {type(raw).__name__}")


class _RpcEmulatorResp(BaseJsonRpcModel):
    exitCode: str
    externalSolanaCall: bool
    revertBeforeSolanaCall: bool
    revertAfterSolanaCall: bool

    result: EthBinStrField
    numEvmSteps: int
    gasUsed: int
    numIterations: int
    solanaAccounts: list[_RpcSolanaAccountModel]

    @classmethod
    def from_raw(cls, raw: _RpcEmulatorResp | EmulNeonCallResp | None) -> Self | None:
        if raw is None:
            return None
        elif isinstance(raw, _RpcEmulatorResp):
            return raw
        elif isinstance(raw, EmulNeonCallResp):
            return cls(
                exitCode=raw.exit_code,
                externalSolanaCall=raw.external_sol_call,
                revertBeforeSolanaCall=raw.revert_before_sol_call,
                revertAfterSolanaCall=raw.revert_after_sol_call,
                result=raw.result,
                numEvmSteps=raw.evm_step_cnt,
                gasUsed=raw.used_gas,
                numIterations=raw.iter_cnt,
                solanaAccounts=[_RpcSolanaAccountModel.from_raw(a) for a in raw.raw_meta_list],
            )

        raise ValueError(f"Wrong input type: {type(raw).__name__}")


class _RpcNeonSkdSubTxDraft(BaseEthCallModel):
    childTransaction: HexUIntField | None = None
    _NoChildTxIdx: Final[int] = 0xFFFF

    def calc_child_idx(self, idx: int, tx_list_len: int) -> int:
        if (child_idx := idx + 1) >= tx_list_len:
            child_idx = self._NoChildTxIdx
        return if_none(self.childTransaction, child_idx)

    @classmethod
    def calc_has_child(cls, child_idx: int) -> bool:
        return child_idx != cls._NoChildTxIdx

    def to_clean_copy(self, idx: int, parent_cnt: int, tx_list_len: int) -> _RpcNeonSkdSubTxModel:
        param_dict = self.model_dump()
        param_dict.update(dict(childTransaction=self.calc_child_idx(idx, tx_list_len)))
        return _RpcNeonSkdSubTxModel(**param_dict, index=idx, parentCount=parent_cnt)


class _RpcNeonSkdSubTxModel(_RpcNeonSkdSubTxDraft):
    index: int
    parentCount: int

    @cached_property
    def has_child(self) -> bool:
        return self.calc_has_child(self.childTransaction)

    @cached_property
    def is_root_tx(self) -> bool:
        return self.parentCount == 0


class _RpcSolTxAccountModel(BaseJsonRpcModel):
    address: SolPubKeyField
    isSigner: bool
    isWritable: bool

    @cached_method
    def to_meta(self) -> SolAccountMeta:
        return SolAccountMeta(pubkey=self.address, is_signer=self.isSigner, is_writable=self.isWritable)


class _RpcSolTxIxModel(BaseJsonRpcModel):
    accountList: list[_RpcSolTxAccountModel] = Field(default_factory=list, validation_alias="accounts")
    programId: SolPubKeyField
    data: Base58Field

    @cached_method
    def to_sol_tx_ix(self) -> SolTxIx:
        return SolTxIx(program_id=self.programId, data=self.data, accounts=[a.to_meta() for a in self.accountList])

    def model_post_init(self, _ctx: Any) -> None:
        if not self.accountList:
            raise ValueError("accountList should be present")


class _RpcSolTxModel(BaseJsonRpcModel):
    instructions: list[_RpcSolTxIxModel] = Field(default_factory=list)

    @cached_method
    def to_sol_tx(self) -> SolTx:
        return SolLegacyTx(name="rpc", ix_list=[ix.to_sol_tx_ix() for ix in self.instructions])

    def model_post_init(self, _ctx: Any) -> None:
        if not self.instructions:
            raise ValueError("instructions should be present")


class _RpcNeonSkdTxRequest(BaseEthGasModel):
    txType: HexUIntField = Field(default=NeonTxType.Scheduled.value, validation_alias="type")
    scheduledSolanaPayer: SolPubKeyField
    solTxList: list[_RpcSolTxModel] = Field(default_factory=list, validation_alias="preparatorySolanaTransactions")
    draftTxList: list[_RpcNeonSkdSubTxDraft] = Field(default_factory=list, validation_alias="transactions")

    _maxTxListLen: Final[int] = 24

    @cached_property
    def txList(self) -> list[_RpcNeonSkdSubTxModel]:
        tx_list_len = len(self.draftTxList)
        parent_cnt_list: list[int] = [0] * tx_list_len
        for idx, tx in enumerate(self.draftTxList):
            child_idx = tx.calc_child_idx(idx, tx_list_len)
            if not tx.calc_has_child(child_idx):
                pass
            elif child_idx <= idx:
                raise ValueError(f"childTransaction {child_idx} in {idx} should be more than {idx}")
            elif child_idx >= tx_list_len:
                raise ValueError(f"childTransaction {child_idx} in {idx} should be less than {tx_list_len}")
            else:
                parent_cnt_list[child_idx] += 1

        return [tx.to_clean_copy(idx, parent_cnt_list[idx], tx_list_len) for idx, tx in enumerate(self.draftTxList)]

    def model_post_init(self, _ctx: Any) -> None:
        if not NeonTxType.is_scheduled_tx(self.txType):
            raise ValueError(f"type should be {NeonTxType.Scheduled.value}")
        elif self.scheduledSolanaPayer.is_empty:
            raise ValueError("scheduledSolanaPayer should be present")
        elif self.maxPriorityFeePerGas > self.maxFeePerGas:
            raise ValueError("maxPriorityFeePerGas should be not greater than maxFeePerGas")
        elif not self.draftTxList:
            raise ValueError("transactions should be present")
        elif len(self.draftTxList) > self._maxTxListLen:
            raise ValueError(f"transaction list is too long, should be less than {self._maxTxListLen}")

        null_cnt = sum(map(lambda x: 1 if x.childTransaction is None else 0, self.draftTxList))
        if null_cnt not in (0, len(self.draftTxList)):
            raise ValueError("childTransaction should be present for all or none of the transactions")

    def validate_chain_id(self, chain_id: int) -> None:
        if (self.chainId or chain_id) != chain_id:
            raise EthWrongChainIdError()

    def to_core_tx_list(self, chain_id: int) -> list[CoreApiTxModel]:
        payer = NeonAddress.from_raw(self.scheduledSolanaPayer, chain_id).eth_address
        return [
            CoreApiTxModel(
                from_address=self.scheduledSolanaPayer if tx.fromAddress == payer else tx.fromAddress,
                payer=payer,
                solanaPayer=self.scheduledSolanaPayer,
                to_address=tx.toAddress,
                nonce=self.nonce,
                value=tx.value,
                call_data=tx.call_data.to_bytes(),
                gas_limit=tx.gas,
                gas_price=(self.maxFeePerGas - self.maxPriorityFeePerGas),
                chain_id=chain_id,
            )
            for tx in self.txList
        ]

    @cached_method
    def to_sol_tx_list(self) -> list[SolTx]:
        return [tx.to_sol_tx() for tx in self.solTxList]


class _RpcSkdTxEstimateResp(BaseJsonRpcModel):
    chainId: HexUIntField
    maxFeePerGas: HexUIntField
    maxPriorityFeePerGas: HexUIntField
    nonce: HexUIntField
    treasuryIndex: HexUIntField
    accountList: list[SolPubKeyField]
    gasList: list[HexUIntField]


class NpCallApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::CallAndEmulate"

    @cached_property
    def _gas_limit_calc(self) -> RpcNeonGasLimitCalculator:
        return RpcNeonGasLimitCalculator(self._server)

    @NeonProxyApi.method(name="eth_call")
    async def eth_call(
        self,
        ctx: HttpRequestCtx,
        tx: RpcEthTxRequest,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
        _object_state: _RpcEthStateRequest = _RpcEthStateRequest.default(),
    ) -> EthBinStrField:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(tx.fromAddress, SolPubKey))
        block = await self.get_block_by_tag(block_tag)
        resp = await self._core_api_client.emulate_neon_call(
            tx.to_core_tx(chain_id),
            check_result=True,
            block=block,
        )
        return resp.result

    @NeonProxyApi.method(name="eth_estimateGas")
    async def estimate_gas(
        self,
        ctx: HttpRequestCtx,
        call: RpcEthTxRequest,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(call.fromAddress, SolPubKey))
        block = await self.get_block_by_tag(block_tag)
        return await self._gas_limit_calc.estimate(call.to_core_tx(chain_id), dict(), block)

    @NeonProxyApi.method(name="neon_estimateGas")
    async def neon_estimate_gas(
        self,
        ctx: HttpRequestCtx,
        tx: RpcEthTxRequest,
        neon_call: RpcNeonCallRequest = RpcNeonCallRequest.default(),
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        chain_id = self._validate_layer0_chain_id(ctx, isinstance(tx.fromAddress, SolPubKey))
        block = await self.get_block_by_tag(block_tag)
        return await self._gas_limit_calc.estimate(tx.to_core_tx(chain_id), neon_call.sol_account_dict, block)

    @NeonProxyApi.method(name="neon_emulate")
    async def neon_emulate(
        self,
        ctx: HttpRequestCtx,
        raw_signed_tx: EthBinStrField,
        neon_call: RpcNeonCallRequest = RpcNeonCallRequest.default(),
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> _RpcEmulatorResp:
        """Executes emulator with given transaction"""
        chain_id = self._get_chain_id(ctx)
        block = await self.get_block_by_tag(block_tag)

        try:
            neon_tx = NeonTxModel.from_raw(raw_signed_tx.to_bytes(), raise_exception=True)
        except EthError:
            raise
        except (BaseException,):
            raise InvalidParamError(message="wrong transaction format")

        if neon_tx.has_chain_id:
            if neon_tx.chain_id != chain_id:
                raise EthWrongChainIdError()
        elif not self._is_default_chain_id(ctx):
            raise EthWrongChainIdError()

        resp = await self._core_api_client.emulate_neon_call(
            CoreApiTxModel.from_neon_tx(neon_tx),
            check_result=False,
            sol_account_dict=neon_call.sol_account_dict,
            block=block,
        )
        return _RpcEmulatorResp.from_raw(resp)

    @NeonProxyApi.method(name="neon_estimateScheduledGas")
    async def neon_estimate_skd_tx(
        self,
        ctx: HttpRequestCtx,
        call: _RpcNeonSkdTxRequest,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> _RpcSkdTxEstimateResp:
        chain_id = self._validate_layer0_chain_id(ctx)
        call.validate_chain_id(chain_id)

        block = await self.get_block_by_tag(block_tag)

        sender_addr = NeonAddress.from_raw(call.scheduledSolanaPayer, chain_id)
        sender_acct = await self._core_api_client.get_neon_account(sender_addr, block)
        if if_none(call.nonce, sender_acct.state_tx_cnt) != sender_acct.state_tx_cnt:
            raise EthError("nonce mismatch")

        gas_limit_list = await self._estimate_skd_tree_gas(call, chain_id, block)
        _, token_gas_price = await self._get_token_gas_price(ctx)

        base_index = sender_acct.state_tx_cnt + int.from_bytes(sender_addr.to_bytes()[:4], "little")
        treasury_index, _, treasury_addr = NeonProg.calc_treasury_address(base_index)

        skd_tree_addr = NeonSkdTreeAddress.from_raw(sender_addr, sender_acct.state_tx_cnt)

        return _RpcSkdTxEstimateResp(
            chainId=chain_id,
            maxFeePerGas=token_gas_price.suggested_gas_price,
            maxPriorityFeePerGas=token_gas_price.profitable_gas_price,
            nonce=sender_acct.state_tx_cnt,
            treasuryIndex=treasury_index,
            accountList=[
                call.scheduledSolanaPayer,
                sender_acct.sol_address,
                treasury_addr,
                skd_tree_addr.address,
                NeonProg.DepositAddress,
                SolSysProg.ID,
            ],
            gasList=list(gas_limit_list),
        )

    async def _estimate_skd_tree_gas(
        self,
        call: _RpcNeonSkdTxRequest,
        chain_id: int,
        block: NeonBlockHdrModel
    ) -> Sequence[int]:
        tx_list = call.txList
        core_tx_list = call.to_core_tx_list(chain_id)
        sol_tx_list = call.to_sol_tx_list()

        # build all branches from root txs, because they
        core_tx_branch_list: list[list[tuple[int, CoreApiTxModel]]] = list()
        for base_tx in tx_list:
            if not base_tx.is_root_tx:
                continue

            # build branch from the root tx
            tx = base_tx
            core_tx_branch: list[tuple[int, CoreApiTxModel]] = [(tx.index, core_tx_list[tx.index])]
            while tx.has_child:
                tx = tx_list[tx.childTransaction]
                core_tx_branch.append((tx.index, core_tx_list[tx.index]))

            core_tx_branch_list.append(core_tx_branch)

        if len(core_tx_branch_list) == 1:
            return list(await self._gas_limit_calc.estimate_skd_tree(sol_tx_list, core_tx_list, block))

        # run in parallel the gas estimation tasks for all branches
        # fmt: off
        estimate_task_list = [
            self._gas_limit_calc.estimate_skd_tree(
                sol_tx_list,
                list(map(lambda x: x[1], core_tx_branch)),
                block,
            )
            for core_tx_branch in core_tx_branch_list
        ]
        # fmt: on
        gas_branch_list = await asyncio.gather(*estimate_task_list)

        # get the maximum gas from each branch
        gas_list: list[int] = [0] * len(tx_list)
        for gas_branch, core_tx_branch in zip(gas_branch_list, core_tx_branch_list):
            for gas, core_idx_tx in zip(gas_branch, core_tx_branch):
                idx, _ = core_idx_tx
                gas_list[idx] = max(gas_list[idx], gas)
        return gas_list

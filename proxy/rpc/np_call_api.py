from __future__ import annotations

from typing import ClassVar, Any

from pydantic import Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthWrongChainIdError, EthError
from common.ethereum.hash import EthAddressField, EthHash32Field
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.jsonrpc.errors import InvalidParamError
from common.neon.address import NeonAddress
from common.neon.neon_program import NeonProg
from common.neon.skd_tree import NeonSkdTreeAddress
from common.neon.transaction_model import NeonTxModel, NeonTxType
from common.neon_rpc.api import EmulAccountMetaModel, EmulNeonCallResp, CoreApiTxModel
from common.solana.pubkey import SolPubKeyField
from common.solana.sys_program import SolSysProg
from common.utils.cached import cached_property
from common.utils.format import if_none
from common.utils.pydantic import HexUIntField, RootModel
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


_RpcNeonSkdSubTxModel = BaseEthCallModel


class _RpcNeonSkdTxRequest(BaseEthGasModel):
    txType: HexUIntField = Field(default=NeonTxType.Scheduled.value, validation_alias="type")
    scheduledSolanaPayer: SolPubKeyField
    txList: list[_RpcNeonSkdSubTxModel] = Field(default_factory=list, validation_alias="transactions")

    def model_post_init(self, _ctx: Any) -> None:
        if not NeonTxType.is_scheduled_tx(self.txType):
            raise ValueError(f"type should be {NeonTxType.Scheduled.value}")
        if self.scheduledSolanaPayer.is_empty:
            raise ValueError("scheduledSolanaPayer should be present")
        if self.maxPriorityFeePerGas > self.maxFeePerGas:
            raise ValueError("maxPriorityFeePerGas should be not greater than maxFeePerGas")
        if not self.txList:
            raise ValueError("transactions should be present")

    def validate_chain_id(self, chain_id: int) -> None:
        if (self.chainId or chain_id) != chain_id:
            raise ValueError(f"chainId should equal to {chain_id}")

    def to_core_tx_list(self, chain_id: int) -> list[CoreApiTxModel]:
        return [
            CoreApiTxModel(
                from_address=tx.fromAddress,
                payer=NeonAddress.from_raw(self.scheduledSolanaPayer, 0).eth_address,
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
        object_state: _RpcEthStateRequest = _RpcEthStateRequest.default(),
    ) -> EthBinStrField:
        _ = object_state
        chain_id = self._get_tx_chain_id(ctx, tx)
        block = await self.get_block_by_tag(block_tag)
        evm_cfg = await self._get_evm_cfg()
        resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
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
        chain_id = self._get_tx_chain_id(ctx, call)
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
        chain_id = self._get_tx_chain_id(ctx, tx)
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
        evm_cfg = await self._get_evm_cfg()
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
            evm_cfg,
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
        self._validate_layer0_chain_id(ctx)

        chain_id = self._get_chain_id(ctx)
        call.validate_chain_id(chain_id)

        block = await self.get_block_by_tag(block_tag)

        sender_addr = NeonAddress.from_raw(call.scheduledSolanaPayer, chain_id)
        sender_acct = await self._core_api_client.get_neon_account(sender_addr, block)
        if if_none(call.nonce, sender_acct.state_tx_cnt) != sender_acct.state_tx_cnt:
            raise EthError("nonce mismatch")

        gas_limit_list = await self._gas_limit_calc.estimate_skd_tree(call.to_core_tx_list(chain_id))

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

    def _get_tx_chain_id(self, ctx: HttpRequestCtx, tx: RpcEthTxRequest) -> int:
        chain_id = self._get_chain_id(ctx)
        if tx.chainId and tx.chainId != chain_id:
            raise EthWrongChainIdError()
        return chain_id

from __future__ import annotations

from typing import ClassVar

from pydantic import Field
from typing_extensions import Self

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthWrongChainIdError
from common.ethereum.hash import EthAddressField, EthHash32Field
from common.http.utils import HttpRequestCtx
from common.jsonrpc.api import BaseJsonRpcModel
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EmulatorAccountModel, EmulatorResp
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import HexUIntField, RootModel
from .api import RpcCallRequest, RpcBlockRequest, RpcNeonCallRequest
from .gas_limit_calculator import NpGasLimitCalculator
from .server_abc import NeonProxyApi


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
    def from_raw(cls, raw: _RpcSolanaAccountModel | EmulatorAccountModel | None) -> Self | None:
        if raw is None:
            return None
        elif isinstance(raw, _RpcSolanaAccountModel):
            return raw
        elif isinstance(raw, EmulatorAccountModel):
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
    solanaAccounts: tuple[_RpcSolanaAccountModel, ...]

    @classmethod
    def from_raw(cls, raw: _RpcEmulatorResp | EmulatorResp | None) -> Self | None:
        if raw is None:
            return None
        elif isinstance(raw, _RpcEmulatorResp):
            return raw
        elif isinstance(raw, EmulatorResp):
            return cls(
                exitCode=raw.exit_code,
                externalSolanaCall=raw.external_solana_call,
                revertBeforeSolanaCall=raw.revert_before_solana_call,
                revertAfterSolanaCall=raw.revert_after_solana_call,
                result=raw.result,
                numEvmSteps=raw.evm_step_cnt,
                gasUsed=raw.used_gas,
                numIterations=raw.iter_cnt,
                solanaAccounts=tuple([_RpcSolanaAccountModel.from_raw(a) for a in raw.raw_meta_list]),
            )

        raise ValueError(f"Wrong input type: {type(raw).__name__}")


class NpCallApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::CallAndEmulate"

    @property
    def _gas_limit_calc(self) -> NpGasLimitCalculator:
        return self._server._gas_limit_calc  # noqa

    @NeonProxyApi.method(name="eth_call")
    async def eth_call(
        self,
        ctx: HttpRequestCtx,
        call: RpcCallRequest,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
        object_state: _RpcEthStateRequest = _RpcEthStateRequest.default(),
    ) -> EthBinStrField:
        chain_id = self.get_chain_id(ctx)
        if call.chainId and call.chainId != chain_id:
            raise EthWrongChainIdError()

        _ = object_state
        block = await self.get_block_by_tag(block_tag)
        evm_cfg = await self.get_evm_cfg()
        resp = await self._core_api_client.emulate(
            evm_cfg,
            call.fromAddress,
            call.toAddress,
            call.value,
            call.data,
            call.gas,
            call.gasPrice,
            chain_id,
            preload_sol_address_list=tuple(),
            sol_account_dict=dict(),
            check_result=True,
            block=block,
        )
        return resp.result

    @NeonProxyApi.method(name="eth_estimateGas")
    async def estimate_gas(
        self,
        ctx: HttpRequestCtx,
        call: RpcCallRequest,
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        chain_id = self.get_chain_id(ctx)
        if call.chainId and call.chainId != chain_id:
            raise EthWrongChainIdError()

        block = await self.get_block_by_tag(block_tag)
        return await self._gas_limit_calc.estimate(call, chain_id, None, block)

    @NeonProxyApi.method(name="neon_estimateGas")
    async def neon_estimate_gas(
        self,
        ctx: HttpRequestCtx,
        call: RpcCallRequest,
        neon_call: RpcNeonCallRequest = RpcCallRequest.default(),
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> HexUIntField:
        chain_id = self.get_chain_id(ctx)
        if call.chainId and call.chainId != chain_id:
            raise EthWrongChainIdError()

        block = await self.get_block_by_tag(block_tag)
        return await self._gas_limit_calc.estimate(call, chain_id, neon_call, block)

    @NeonProxyApi.method(name="neon_emulate")
    async def neon_emulate(
        self,
        ctx: HttpRequestCtx,
        raw_signed_tx: str,
        neon_call: RpcNeonCallRequest = RpcNeonCallRequest.default(),
        block_tag: RpcBlockRequest = RpcBlockRequest.latest(),
    ) -> _RpcEmulatorResp:
        """Executes emulator with given transaction"""
        evm_cfg = await self.get_evm_cfg()
        chain_id = self.get_chain_id(ctx)
        block = await self.get_block_by_tag(block_tag)

        neon_tx = NeonTxModel.from_raw(raw_signed_tx)

        resp = await self._core_api_client.emulate_tx(
            evm_cfg,
            neon_tx,
            chain_id,
            preload_sol_address_list=tuple(),
            sol_account_dict=neon_call.sol_account_dict,
            check_result=True,
            block=block,
        )
        return _RpcEmulatorResp.from_raw(resp)

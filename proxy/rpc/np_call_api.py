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
from common.neon_rpc.api import EmulAccountMetaModel, EmulNeonCallResp, CoreApiTxModel
from common.solana.pubkey import SolPubKeyField
from common.utils.cached import cached_property
from common.utils.pydantic import HexUIntField, RootModel
from .api import RpcBlockRequest, RpcNeonCallRequest
from .server_abc import NeonProxyApi
from ..base.rpc_gas_limit_calculator import RpcNeonGasLimitCalculator
from ..base.rpc_api import RpcEthTxRequest


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
    solanaAccounts: tuple[_RpcSolanaAccountModel, ...]

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
                solanaAccounts=tuple([_RpcSolanaAccountModel.from_raw(a) for a in raw.raw_meta_list]),
            )

        raise ValueError(f"Wrong input type: {type(raw).__name__}")


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

        neon_tx = NeonTxModel.from_raw(raw_signed_tx.to_bytes())
        if neon_tx.has_chain_id:
            if neon_tx.chain_id != chain_id:
                raise EthWrongChainIdError()
        elif not self._is_default_chain_id(ctx):
            raise EthWrongChainIdError()

        resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            CoreApiTxModel.from_neon_tx(neon_tx, chain_id),
            check_result=False,
            sol_account_dict=neon_call.sol_account_dict,
            block=block,
        )
        return _RpcEmulatorResp.from_raw(resp)

    def _get_tx_chain_id(self, ctx: HttpRequestCtx, tx: RpcEthTxRequest) -> int:
        chain_id = self._get_chain_id(ctx)
        if tx.chainId and tx.chainId != chain_id:
            raise EthWrongChainIdError()
        return chain_id

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import Sequence, Final, ClassVar
from typing_extensions import Self

from common.ethereum.errors import EthError
from common.ethereum.hash import EthTxHash
from common.ethereum.transaction import EthTx, EthTxType
from common.neon.block import NeonBlockHdrModel
from common.neon.cu_cost_packed import CuCostPktData
from common.neon.neon_program import NeonProg, NeonIxMode
from common.neon_rpc.api import EmulNeonCallResp, CoreApiTxModel
from common.solana.account import SolAccountModel
from common.solana.alt_program import SolAltProg
from common.solana.cb_program import SolCbProg
from common.solana.hash import SolBlockHash
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.utils.cached import cached_property
from .rpc_server_abc import BaseRpcServerComponent

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class RpcGasLimitResult:
    holder_gas: int
    alt_gas: int
    exec_gas: int
    finish_gas: int

    cu_price: int
    cu_gas: int

    exit_code: str
    external_sol_call: bool
    revert_before_sol_call: bool
    revert_after_sol_call: bool
    result: bytes

    evm_step_cnt: int
    iter_cnt: int
    raw_meta_list: list

    _default: ClassVar[RpcGasLimitResult | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(
                holder_gas=0,
                alt_gas=0,
                exec_gas=0,
                finish_gas=0,
                cu_price=0,
                cu_gas=0,
                exit_code="",
                external_sol_call=False,
                revert_before_sol_call=False,
                revert_after_sol_call=False,
                result=bytes(),
                evm_step_cnt=0,
                iter_cnt=0,
                raw_meta_list=list(),
            )
        return cls._default

    @cached_property
    def total_gas(self) -> int:
        return max(
            self.holder_gas + self.alt_gas + self.exec_gas + self.finish_gas + self.cu_gas,
            NeonProg.MinTxCost,
        )


@dataclasses.dataclass(frozen=True)
class _CuCostInfo:
    price: int
    gas: int


class RpcNeonGasLimitCalculator(BaseRpcServerComponent):
    _u64_max: Final[int] = int.from_bytes(bytes([0xFF] * 8), "big")

    # These values aren't used on real network, they are used only to generate temporary data
    _holder_addr = SolPubKey.new_unique()
    _token_sol_addr = SolPubKey.new_unique()
    _payer = SolSigner.fake()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cb_prog = SolCbProg()

    async def estimate(
        self,
        core_tx: CoreApiTxModel,
        sol_account_dict: dict[SolPubKey, SolAccountModel],
        block: NeonBlockHdrModel | None = None,
    ) -> RpcGasLimitResult:
        resp = await self._core_api_client.emulate_neon_call(
            core_tx,
            check_result=True,
            sol_account_dict=sol_account_dict,
            block=block,
        )
        return await self._calc_gas(core_tx, resp)

    async def estimate_skd_tree(
        self,
        sol_tx_list: Sequence[SolTx],
        core_tx_list: Sequence[CoreApiTxModel],
        block: NeonBlockHdrModel | None = None,
    ) -> Sequence[RpcGasLimitResult]:
        resp_list = await self._core_api_client.emulate_multiple_neon_call(
            sol_tx_list,
            core_tx_list,
            check_result=True,
            block=block,
        )
        # fmt: off
        return await asyncio.gather(*[
            self._calc_gas(core_tx, resp, finish_gas=NeonProg.FinishSkdTxGas)
            for core_tx, resp in zip(core_tx_list, resp_list)
        ])
        # fmt: on

    async def _calc_gas(self, core_tx: CoreApiTxModel, resp: EmulNeonCallResp, *, finish_gas: int = 0) -> RpcGasLimitResult:
        exec_gas = resp.used_gas
        tx_size_gas = self._tx_size_gas(core_tx)
        alt_gas = self._alt_gas(resp)

        base_gas = exec_gas + tx_size_gas + alt_gas + finish_gas
        cu = await self._sol_cu_gas(resp, base_gas)

        return RpcGasLimitResult(
            holder_gas=tx_size_gas,
            alt_gas=alt_gas,
            exec_gas=exec_gas,
            finish_gas=finish_gas,
            cu_price=cu.price,
            cu_gas=cu.gas,
            exit_code=resp.exit_code,
            external_sol_call=resp.external_sol_call,
            revert_before_sol_call=resp.revert_before_sol_call,
            revert_after_sol_call=resp.revert_after_sol_call,
            result=resp.result,
            evm_step_cnt=resp.evm_step_cnt,
            iter_cnt=resp.iter_cnt,
            raw_meta_list=resp.raw_meta_list,
        )

    def _tx_size_gas(self, core_tx: CoreApiTxModel) -> int:
        eth_tx = self._eth_tx_from_core_tx(core_tx)
        rlp_tx = eth_tx.to_bytes()
        return self._holder_tx_gas(rlp_tx)

    @classmethod
    def _eth_tx_from_core_tx(cls, core_tx: CoreApiTxModel) -> EthTx:
        return EthTx(
            type=EthTxType.DynamicGas,
            nonce=cls._u64_max,
            max_fee_per_gas=cls._u64_max,
            max_priority_fee_per_gas=cls._u64_max,
            gas_limit=core_tx.gas_limit,
            to_address=core_tx.to_address.to_bytes(),
            value=core_tx.value or cls._u64_max,
            call_data=core_tx.call_data.to_bytes(),
            chain_id=cls._u64_max,
            access_list=list(),
            v=245022934 * 1024 + 35,
            r=0x1820182018201820182018201820182018201820182018201820182018201820,
            s=0x1820182018201820182018201820182018201820182018201820182018201820,
        )

    @cached_property
    def _neon_prog(self) -> NeonProg:
        neon_prog = NeonProg(self._payer.pubkey)
        neon_prog.init_holder_address(self._holder_addr)
        neon_prog.init_token_address(self._token_sol_addr)
        return neon_prog

    def _sol_tx_from_eth_tx(self, eth_tx: EthTx, resp: EmulNeonCallResp) -> SolLegacyTx:
        cb_prog = self._cb_prog

        neon_prog = self._neon_prog
        neon_prog.init_neon_tx(EthTxHash.from_raw(eth_tx.neon_tx_hash), eth_tx.to_bytes())
        neon_prog.init_account_meta_list(resp.sol_account_meta_list)

        neon_ix = neon_prog.make_tx_step_from_data_ix(NeonIxMode.Default, self._cfg.max_emulate_evm_step_cnt, 101)

        ix_list = tuple([
            cb_prog.make_cu_price_ix(cb_prog.BaseCuPrice),
            cb_prog.make_heap_size_ix(cb_prog.MaxHeapSize),
            cb_prog.make_cu_limit_ix(cb_prog.MaxCuLimit),
            neon_ix,
        ])

        sol_tx = SolLegacyTx(name="Estimate", ix_list=ix_list)
        sol_tx.recent_block_hash = SolBlockHash.fake()
        return sol_tx

    @staticmethod
    def _holder_tx_gas(rlp_tx: bytes) -> int:
        return ((len(rlp_tx) // NeonProg.HolderMsgSize) + 1) * 5000

    def _alt_gas(self, resp: EmulNeonCallResp) -> int:
        """
        Gas for:
         - create
         - N extend
         - deactivate
         - close
        """
        acc_cnt = len(resp.raw_meta_list) + NeonProg.BaseAccountCnt
        if acc_cnt > self._cfg.max_tx_account_cnt:
            raise EthError(code=3, message=f"too many accounts: {acc_cnt} > {self._cfg.max_tx_account_cnt}")

        if acc_cnt >= SolAltProg.MaxTxAccountCnt:
            return 5000 * 12  # ALT ix: create + ceil((256-27)/27) extend + deactivate + close
        return 0

    async def _sol_cu_gas(self, resp: EmulNeonCallResp, base_gas: int) -> _CuCostInfo:
        acct_key_list = [a.pubkey for a in resp.raw_meta_list if a.is_writable]
        cu_price = await self._cu_price_client.get_cu_price(acct_key_list)

        iter_cnt = min(NeonProg.MinIterCnt, resp.iter_cnt)

        pkt = CuCostPktData.from_raw(base_gas, iter_cnt, cu_price)
        cu_gas = pkt.tx_cu_cost

        return _CuCostInfo(gas=cu_gas, price=cu_price)

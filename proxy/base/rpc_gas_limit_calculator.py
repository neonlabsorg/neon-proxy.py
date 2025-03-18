from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import Sequence, Final, ClassVar
from typing_extensions import Self

from common.ethereum.errors import EthError
from common.ethereum.hash import EthTxHash
from common.ethereum.transaction import EthTx
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonProg, NeonIxMode
from common.neon_rpc.api import EmulNeonCallResp, CoreApiTxModel
from common.solana.account import SolAccountModel
from common.solana.alt_program import SolAltProg
from common.solana.cb_program import SolCbProg
from common.solana.errors import SolTxSizeError
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
    priority_gas: int

    exit_code: str
    external_sol_call: bool
    revert_before_sol_call: bool
    revert_after_sol_call: bool
    result: bytes

    evm_step_cnt: int
    iter_cnt: int
    raw_meta_list: list

    # Ethereum's wallets don't accept gas limit less than 21'000
    _min_total_gas: Final[int] = 25_000  # minimal gas limit for NeonTx: start (10k), execute (10k), finalization (5k)

    _default: ClassVar[RpcGasLimitResult | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(
                holder_gas=0,
                alt_gas=0,
                exec_gas=0,
                finish_gas=0,
                priority_gas=0,
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
            self.holder_gas + self.alt_gas + self.exec_gas + self.finish_gas + self.priority_gas,
            self._min_total_gas,
        )


class RpcNeonGasLimitCalculator(BaseRpcServerComponent):
    _oz_gas_limit: Final[int] = 30_000  # openzeppelin gas-limit check
    _u64_max: Final[int] = int.from_bytes(bytes([0xFF] * 8), "big")
    _round_cu_coeff: Final[int] = SolCbProg.MaxCuPriceMult + 1

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
        tx_size_gas = self._tx_size_gas(core_tx, resp)
        alt_gas = self._alt_gas(resp)
        cu_fee_gas = await self._sol_cu_fee_gas(resp)

        return RpcGasLimitResult(
            holder_gas=tx_size_gas,
            alt_gas=alt_gas,
            exec_gas=exec_gas,
            finish_gas=finish_gas,
            priority_gas=cu_fee_gas,
            exit_code=resp.exit_code,
            external_sol_call=resp.external_sol_call,
            revert_before_sol_call=resp.revert_before_sol_call,
            revert_after_sol_call=resp.revert_after_sol_call,
            result=resp.result,
            evm_step_cnt=resp.evm_step_cnt,
            iter_cnt=resp.iter_cnt,
            raw_meta_list=resp.raw_meta_list,
        )

    def _tx_size_gas(self, core_tx: CoreApiTxModel, resp: EmulNeonCallResp) -> int:
        eth_tx = self._eth_tx_from_core_tx(core_tx)
        if (len(rlp_tx := eth_tx.to_bytes()) > SolTx.PktSize) or core_tx.to_address.is_empty:
            return self._holder_tx_gas(rlp_tx)

        sol_tx = self._sol_tx_from_eth_tx(eth_tx, resp)
        try:
            sol_tx.sign(self._payer)
            sol_tx.serialize()  # <- there will be exception about size

            if resp.used_gas < self._oz_gas_limit:
                return 0
        except SolTxSizeError:
            pass
        except BaseException as exc:
            _LOG.error("error on pack solana tx", exc_info=exc)

        return self._holder_tx_gas(rlp_tx)

    @classmethod
    def _eth_tx_from_core_tx(cls, core_tx: CoreApiTxModel) -> EthTx:
        return EthTx(
            nonce=cls._u64_max,
            gas_price=cls._u64_max,
            gas_limit=core_tx.gas_limit,
            to_address=core_tx.to_address.to_bytes(),
            value=core_tx.value or 1,
            call_data=core_tx.call_data.to_bytes(),
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
            return 5000 * 12  # ALT ix: create + ceil(256/30) extend + deactivate + close
        return 0

    async def _sol_cu_fee_gas(self, resp: EmulNeonCallResp) -> int:
        acct_key_list = [a.pubkey for a in resp.raw_meta_list if a.is_writable]
        base_cu_price = await self._cu_price_client.get_cu_price(acct_key_list)

        # round cu-price to divisible by 10'500
        cu_price_mult = min(base_cu_price // self._cb_prog.BaseCuPrice + 1, self._cb_prog.MaxCuPriceMult)
        cu_price = cu_price_mult * self._cb_prog.BaseCuPrice

        # round priority-fee to divisible by 1'000
        cu_fee = cu_price * self._cb_prog.MaxCuLimit * resp.iter_cnt // self._cb_prog.MicroLamport
        cu_fee = (cu_fee // self._round_cu_coeff + 1) * self._round_cu_coeff

        return cu_fee + cu_price_mult

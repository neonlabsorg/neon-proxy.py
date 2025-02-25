from __future__ import annotations

import logging
from typing import Sequence

from common.ethereum.errors import EthError
from common.ethereum.hash import EthTxHash
from common.ethereum.transaction import EthTx
from common.neon.block import NeonBlockHdrModel
from common.neon.neon_program import NeonProg, NeonIxMode
from common.neon_rpc.api import EvmConfigModel, EmulNeonCallResp, CoreApiTxModel
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


class RpcNeonGasLimitCalculator(BaseRpcServerComponent):
    _oz_gas_limit = 30_000  # openzeppelin gas-limit check
    _min_gas_limit = 25_000  # minimal gas limit for NeonTx: start (10k), execute (10k), finalization (5k)
    _u64_max = int.from_bytes(bytes([0xFF] * 8), "big")

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
    ) -> int:
        evm_cfg = await self._get_evm_cfg()
        resp = await self._core_api_client.emulate_neon_call(
            evm_cfg,
            core_tx,
            check_result=True,
            sol_account_dict=sol_account_dict,
            block=block,
        )
        return self._total_gas(evm_cfg, core_tx, resp)

    async def estimate_skd_tree(
        self,
        core_tx_list: Sequence[CoreApiTxModel],
        block: NeonBlockHdrModel | None = None,
    ) -> Sequence[int]:
        evm_cfg = await self._get_evm_cfg()
        resp_list = await self._core_api_client.emulate_multiple_neon_call(
            evm_cfg,
            core_tx_list,
            check_result=True,
            block=block,
        )
        # fmt: off
        return tuple([
            self._total_gas(evm_cfg, core_tx, resp, finish_gas=evm_cfg.tree_account_finish_tx_gas)
            for core_tx, resp in zip(core_tx_list, resp_list)
        ])
        # fmt: on

    def _total_gas(
        self,
        evm_cfg: EvmConfigModel,
        core_tx: CoreApiTxModel,
        resp: EmulNeonCallResp,
        *,
        finish_gas: int = 0
    ) -> int:
        exec_gas = resp.used_gas
        tx_size_gas = self._tx_size_gas(evm_cfg, core_tx, resp)
        alt_gas = self._alt_gas(resp)

        # Ethereum's wallets don't accept gas limit less than 21'000
        total_gas = max(exec_gas + tx_size_gas + alt_gas + finish_gas, self._min_gas_limit)

        # _LOG.debug(
        #     "total-gas(%s) = execution-gas(%s) + tx-size-gas(%s) + alt-gas(%s) + finish-gas(%s)",
        #     total_gas,
        #     exec_gas,
        #     tx_size_gas,
        #     alt_gas,
        #     finish_gas,
        # )
        return total_gas

    def _tx_size_gas(self, evm_cfg: EvmConfigModel, core_tx: CoreApiTxModel, resp: EmulNeonCallResp) -> int:
        eth_tx = self._eth_tx_from_core_tx(core_tx)
        if (len(rlp_tx := eth_tx.to_bytes()) > SolTx.PktSize) or core_tx.to_address.is_empty:
            return self._holder_tx_gas(evm_cfg, rlp_tx)

        sol_tx = self._sol_tx_from_eth_tx(eth_tx, resp)
        try:
            sol_tx.sign(self._payer)
            sol_tx.serialize()  # <- there will be exception about size

            if resp.used_gas < self._oz_gas_limit:
                return 0
        except SolTxSizeError:
            pass
        except BaseException as exc:
            _LOG.debug("error on pack solana tx", exc_info=exc)

        return self._holder_tx_gas(evm_cfg, rlp_tx)

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

    @classmethod
    def _holder_tx_gas(cls, evm_cfg: EvmConfigModel, rlp_tx: bytes) -> int:
        return ((len(rlp_tx) // evm_cfg.holder_msg_size) + 1) * 5000

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

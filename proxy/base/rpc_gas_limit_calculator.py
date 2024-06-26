from __future__ import annotations

import logging

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
        execution_cost = resp.used_gas
        tx_size_cost = self._tx_size_cost(evm_cfg, core_tx, resp)
        alt_cost = self._alt_cost(resp)

        # Ethereum's wallets don't accept gas limit less than 21000
        total_cost = max(execution_cost + tx_size_cost + alt_cost, self._min_gas_limit)

        _LOG.debug(
            "total-cost(%s) = execution-cost(%s) + tx-size-cost(%s) + alt-cost(%s)",
            total_cost,
            execution_cost,
            tx_size_cost,
            alt_cost,
        )

        return total_cost

    def _tx_size_cost(self, evm_cfg: EvmConfigModel, core_tx: CoreApiTxModel, resp: EmulNeonCallResp) -> int:
        eth_tx = self._eth_tx_from_core_tx(core_tx)
        sol_tx = self._sol_tx_from_eth_tx(eth_tx, resp)

        try:
            sol_tx.sign(self._payer)
            sol_tx.serialize()  # <- there will be exception about size

            if core_tx.to_address.is_empty:  # deploy case
                pass
            elif resp.used_gas < self._oz_gas_limit:
                return 0
        except SolTxSizeError:
            pass
        except BaseException as exc:
            _LOG.debug("error on pack solana tx", exc_info=exc)

        return self._holder_tx_cost(evm_cfg, eth_tx.to_bytes())

    @classmethod
    def _eth_tx_from_core_tx(cls, core_tx: CoreApiTxModel) -> EthTx:
        return EthTx(
            nonce=cls._u64_max,
            gas_price=cls._u64_max,
            gas_limit=core_tx.gas_limit,
            to_address=core_tx.to_address.to_bytes(),
            value=core_tx.value or 1,
            call_data=core_tx.data.to_bytes(),
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
        ix_list = [
            cb_prog.make_heap_size_ix(cb_prog.MaxHeapSize),
            cb_prog.make_cu_limit_ix(cb_prog.MaxCuLimit),
        ]
        if self._cfg.cu_price > 0:
            ix_list.append(cb_prog.make_cu_price_ix(self._cfg.cu_price))

        neon_prog = self._neon_prog
        neon_prog.init_neon_tx(EthTxHash.from_raw(eth_tx.neon_tx_hash), eth_tx.to_bytes())
        neon_prog.init_account_meta_list(resp.sol_account_meta_list)
        ix_list.append(neon_prog.make_tx_step_from_data_ix(NeonIxMode.Default, self._cfg.max_emulate_evm_step_cnt, 101))

        sol_tx = SolLegacyTx(name="Estimate", ix_list=tuple(ix_list))
        sol_tx.recent_block_hash = SolBlockHash.fake()
        return sol_tx

    @classmethod
    def _holder_tx_cost(cls, evm_cfg: EvmConfigModel, eth_tx_rlp: bytes) -> int:
        return ((len(eth_tx_rlp) // evm_cfg.holder_msg_size) + 1) * 5000

    def _alt_cost(self, resp: EmulNeonCallResp) -> int:
        """
        Costs for:
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

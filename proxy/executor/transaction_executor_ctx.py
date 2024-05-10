from __future__ import annotations

import itertools
import logging
from typing import Sequence

from typing_extensions import Self

from common.config.config import Config
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.neon_program import NeonProg
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EmulNeonCallResp, HolderAccountModel, EvmConfigModel
from common.neon_rpc.client import CoreApiClient
from common.solana.alt_program import SolAltID
from common.solana.cb_program import SolCbProg
from common.solana.instruction import SolAccountMeta
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.solana_rpc.client import SolClient
from common.solana_rpc.transaction_list_sender import SolTxListSender, SolTxListSigner
from common.solana_rpc.ws_client import SolWatchTxSession
from common.utils.cached import cached_property, cached_method, reset_cached_method
from .server_abc import ExecutorComponent, ExecutorServerAbc
from .transaction_list_signer import OpTxListSigner
from ..base.ex_api import ExecTxRequest, ExecStuckTxRequest

_LOG = logging.getLogger(__name__)


class NeonExecTxCtx(ExecutorComponent):
    def __init__(self, server: ExecutorServerAbc, tx_request: ExecTxRequest | ExecStuckTxRequest, *, chain_id: int = 0):
        super().__init__(server)
        self._tx_request = tx_request
        self._token_sol_addr = tx_request.resource.token_sol_address

        self._chain_id: int = tx_request.tx.chain_id if isinstance(tx_request, ExecTxRequest) else chain_id
        self._evm_step_cnt_per_iter: int | None = 0

        self._uniq_idx = itertools.count()
        self._alt_id_set: set[SolAltID] = set()
        self._sol_tx_list_dict: dict[str, list[SolTx]] = dict()
        self._has_completed_receipt = False

        self._acct_meta_list: tuple[SolAccountMeta, ...] = tuple()
        self._emulator_resp: EmulNeonCallResp | None = None

        self._test_mode = False

    async def get_evm_cfg(self) -> EvmConfigModel:
        evm_cfg = await self._server.get_evm_cfg()
        self._evm_step_cnt_per_iter = evm_cfg.evm_step_cnt
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.protocol_version)
        return evm_cfg

    @property
    def cfg(self) -> Config:
        return self._cfg

    @property
    def sol_client(self) -> SolClient:
        return self._sol_client

    @property
    def core_api_client(self) -> CoreApiClient:
        return self._core_api_client

    @cached_property
    def sol_tx_list_signer(self) -> SolTxListSigner:
        req = self._tx_request
        tx_id = req.tx.tx_id if isinstance(req, ExecTxRequest) else req.stuck_tx.tx_id
        return OpTxListSigner(tx_id, self.payer, self._op_client)

    @cached_property
    def sol_tx_list_sender(self) -> SolTxListSender:
        watch_session = SolWatchTxSession(self._cfg, self._sol_client)
        return SolTxListSender(self._cfg, watch_session, self.sol_tx_list_signer)

    @property
    def len_account_meta_list(self) -> int:
        return len(self._acct_meta_list)

    @property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return self._get_account_key_list()

    @reset_cached_method
    def _get_account_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple([SolPubKey.from_raw(meta.pubkey) for meta in self._acct_meta_list])

    def set_emulator_result(self, resp: EmulNeonCallResp) -> None:
        assert not self.is_stuck_tx

        _LOG.debug("emulator result contains %d EVM steps, %d iterations", resp.evm_step_cnt, resp.iter_cnt)

        # sort accounts in a predictable order
        acct_meta_list = tuple(sorted(resp.sol_account_meta_list, key=lambda m: bytes(m.pubkey)))
        if acct_meta_list == self._acct_meta_list:
            _LOG.debug("emulator result contains the same %d accounts", len(resp.raw_meta_list))
        else:
            self._get_account_key_list.reset_cache(self)
            self._acct_meta_list = acct_meta_list
            self._neon_prog.init_account_meta_list(self._acct_meta_list)
            self._test_neon_prog.init_account_meta_list(self._acct_meta_list)
            _LOG.debug("emulator result contains %d accounts: %s", len(resp.raw_meta_list), self._FmtAcctMeta(self))

        self._emulator_resp = resp
        self._calc_total_evm_step_cnt.reset_cache(self)
        self._calc_total_iter_cnt.reset_cache(self)
        self._calc_wrap_iter_cnt.reset_cache(self)
        self._calc_resize_iter_cnt.reset_cache(self)

    def set_holder_account(self, holder: HolderAccountModel) -> None:
        assert self.is_stuck_tx
        assert holder.neon_tx_hash == self.neon_tx_hash

        # !don't! sort accounts, use order from the holder
        acct_meta_list = tuple(
            map(lambda x: SolAccountMeta(x, is_signer=False, is_writable=True), holder.account_key_list)
        )

        if acct_meta_list == self._acct_meta_list:
            _LOG.debug("holder contains the same %d accounts", len(holder.account_key_list))
        else:
            self._acct_meta_list = tuple(acct_meta_list)
            self._neon_prog.init_account_meta_list(self._acct_meta_list)
            self._test_neon_prog.init_account_meta_list(self._acct_meta_list)
            _LOG.debug("holder contains %d accounts: %s", len(holder.account_key_list), self._FmtAcctMeta(self))

    class _FmtAcctMeta:
        def __init__(self, ctx: NeonExecTxCtx) -> None:
            self._acct_meta_list = ctx._acct_meta_list

        @cached_method
        def to_string(self) -> str:
            return ", ".join(f"({x.pubkey}, {x.is_writable})" for x in self._acct_meta_list)

        def __repr__(self) -> str:
            return self.to_string()

        def __str__(self) -> str:
            return self.to_string()

    @cached_property
    def cb_prog(self) -> SolCbProg:
        return SolCbProg()

    def test_mode(self) -> _TestMode:
        return self._TestMode(self)

    class _TestMode:
        def __init__(self, ctx: NeonExecTxCtx) -> None:
            self._ctx = ctx

        def __enter__(self) -> Self:
            self._ctx._test_mode = True
            return self

        def __exit__(self, exc_type, exc_val, exc_tb) -> Self:
            self._ctx._test_mode = False
            if exc_val:
                raise
            return self

    @property
    def neon_prog(self) -> NeonProg:
        if self._test_mode:
            return self._test_neon_prog
        return self._neon_prog

    @cached_property
    def _neon_prog(self) -> NeonProg:
        return self._new_neon_prog(self.payer)

    @cached_property
    def _test_neon_prog(self) -> NeonProg:
        return self._new_neon_prog(SolSigner.fake().pubkey)

    def _new_neon_prog(self, payer: SolPubKey) -> NeonProg:
        prog = NeonProg(payer).init_holder_address(self.holder_address)

        assert not self._token_sol_addr.is_empty
        prog.init_token_address(self._token_sol_addr)

        if not self.is_stuck_tx:
            eth_rlp_tx = self._tx_request.tx.eth_tx_data.to_bytes()
        else:
            eth_rlp_tx = bytes()
        prog.init_neon_tx(self.neon_tx_hash, eth_rlp_tx)

        return prog

    def set_token_sol_address(self, token_address: SolPubKey) -> None:
        assert not token_address.is_empty
        assert self._token_sol_addr.is_empty
        self._token_sol_addr = token_address

    @cached_property
    def is_stuck_tx(self) -> bool:
        return isinstance(self._tx_request, ExecStuckTxRequest)

    @cached_property
    def payer(self) -> SolPubKey:
        return self._tx_request.resource.owner

    @property
    def holder_address(self) -> SolPubKey:
        if self.is_stuck_tx:
            return self._tx_request.stuck_tx.holder_address
        return self._tx_request.resource.holder_address

    @cached_property
    def neon_tx(self) -> NeonTxModel:
        assert not self.is_stuck_tx
        return self._tx_request.tx.neon_tx

    @cached_property
    def neon_tx_hash(self) -> EthTxHash:
        if self.is_stuck_tx:
            return self._tx_request.stuck_tx.neon_tx_hash
        return self._tx_request.tx.neon_tx_hash

    @cached_property
    def has_chain_id(self) -> bool:
        if self.is_stuck_tx:
            return True
        return self._tx_request.tx.neon_tx.has_chain_id

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @cached_property
    def sender(self) -> NeonAccount:
        assert not self.is_stuck_tx
        return NeonAccount.from_raw(self._tx_request.tx.sender, self.chain_id)

    def next_uniq_idx(self) -> int:
        return next(self._uniq_idx)

    @property
    def evm_step_cnt_per_iter(self) -> int:
        return self._evm_step_cnt_per_iter

    @property
    def total_evm_step_cnt(self) -> int:
        return self._calc_total_evm_step_cnt()

    @reset_cached_method
    def _calc_total_evm_step_cnt(self) -> int:
        if self.is_stuck_tx:
            assert not self._emulator_resp
            _LOG.debug("stuck-tx -> no information about emulated evm steps")
            return self._evm_step_cnt_per_iter

        assert self._emulator_resp
        return self._emulator_resp.evm_step_cnt

    @property
    def total_iter_cnt(self) -> int:
        return self._calc_total_iter_cnt()

    @reset_cached_method
    def _calc_total_iter_cnt(self) -> int:
        assert not self.is_stuck_tx
        assert self._emulator_resp

        return self._emulator_resp.iter_cnt

    @property
    def wrap_iter_cnt(self) -> int:
        return self._calc_wrap_iter_cnt()

    @reset_cached_method
    def _calc_wrap_iter_cnt(self) -> int:
        evm_step_cnt = self._evm_step_cnt_per_iter
        exec_iter_cnt = (self.total_evm_step_cnt + evm_step_cnt - 1) // evm_step_cnt
        iter_cnt = self.total_iter_cnt - exec_iter_cnt
        assert iter_cnt >= 0
        return iter_cnt

    @property
    def resize_iter_cnt(self) -> int:
        return self._calc_resize_iter_cnt()

    @reset_cached_method
    def _calc_resize_iter_cnt(self) -> int:
        iter_cnt = self.wrap_iter_cnt - 2  # 1 begin + 1 end
        assert iter_cnt >= 0
        return iter_cnt

    @property
    def has_external_solana_call(self) -> bool:
        assert not self.is_stuck_tx
        assert self._emulator_resp

        return self._emulator_resp.external_solana_call

    @property
    def alt_id_list(self) -> tuple[SolAltID, ...]:
        return tuple(self._alt_id_set)

    def add_alt_id(self, alt_id: SolAltID) -> None:
        self._alt_id_set.add(alt_id)

    @property
    def has_good_sol_tx_receipt(self) -> bool:
        return self._has_completed_receipt

    def mark_good_sol_tx_receipt(self) -> None:
        self._has_completed_receipt = True

    def has_sol_tx(self, name: str) -> bool:
        return name in self._sol_tx_list_dict

    def pop_sol_tx_list(self, tx_name_list: tuple[str, ...]) -> tuple[SolTx, ...]:
        tx_list: list[SolTx] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_tx_list_dict.pop(tx_name, None):
                tx_list.extend(tx_sublist)
        return tuple(tx_list)

    def add_sol_tx_list(self, tx_list: Sequence[SolTx]) -> None:
        for tx in tx_list:
            self._sol_tx_list_dict.setdefault(tx.name, list()).append(tx)

from __future__ import annotations

import itertools
import logging
from typing import Sequence, Final

from typing_extensions import Self

from common.atlas.fee_client import AtlasFeeClient
from common.config.config import Config
from common.ethereum.hash import EthTxHash
from common.neon.account import NeonAccount
from common.neon.neon_program import NeonProg, NeonBaseTxAccountSet
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import (
    EmulNeonCallResp,
    HolderAccountModel,
    EvmConfigModel,
    CoreApiTxModel,
    CoreApiBlockModel,
)
from common.neon_rpc.client import CoreApiClient
from common.solana.alt_program import SolAltID, SolAltProg
from common.solana.cb_program import SolCbProg
from common.solana.instruction import SolAccountMeta
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.sys_program import SolSysProg
from common.solana.token_program import SplTokenProg
from common.solana.transaction import SolTx
from common.solana_rpc.client import SolClient
from common.solana_rpc.transaction_list_sender import SolTxListSigner
from common.utils.cached import cached_property, cached_method, reset_cached_method
from indexer.db.indexer_db_client import IndexerDbClient
from .transaction_list_signer import OpTxListSigner
from ..base.ex_api import ExecTxRequest, ExecStuckTxRequest
from ..base.op_client import OpResourceClient
from ..stat.client import StatClient

_LOG = logging.getLogger(__name__)


class NeonExecTxCtx:
    # TODO: remove after re-emulate implementation
    _global_ro_addr_set: Final[frozenset[SolPubKey]] = frozenset(
        [
            NeonProg.ID,
            SolCbProg.ID,
            SolAltProg.ID,
            SplTokenProg.ID,
            SolSysProg.ID,
            SolSysProg.ClockVar,
            SolSysProg.RecentBlockHashVar,
            SolSysProg.RentVar,
            SolSysProg.RewardVar,
            SolSysProg.StakeHistoryVar,
            SolSysProg.EpochScheduleVar,
            SolSysProg.IxListVar,
            SolSysProg.SlotHashVar,
            # Some popular addresses
            SolPubKey.from_raw("1nc1nerator11111111111111111111111111111111"),
            SolPubKey.from_raw("p1exdMJcjVao65QdewkaZRUnU6VPSXhus9n2GzWfh98"),  # metaplex
            SolPubKey.from_raw("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),  # USDC
            SolPubKey.from_raw("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),  # USDT
            SolPubKey.from_raw("So11111111111111111111111111111111111111112"),  # wSOL
            SolPubKey.from_raw("7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs"),  # wETH
        ]
    )

    def __init__(
        self,
        cfg: Config,
        sol_client: SolClient,
        core_api_client: CoreApiClient,
        op_client: OpResourceClient,
        fee_client: AtlasFeeClient,
        stat_client: StatClient,
        db: IndexerDbClient,
        tx_request: ExecTxRequest | ExecStuckTxRequest,
    ) -> None:
        self._cfg = cfg
        self._sol_client = sol_client
        self._core_api_client = core_api_client
        self._op_client = op_client
        self._fee_client = fee_client
        self._stat_client = stat_client
        self._db = db

        self._tx_request = tx_request
        self._holder: HolderAccountModel | None = None

        self._token_sol_addr = tx_request.resource.token_sol_address
        self._evm_step_cnt_per_iter: int | None = 0

        self._uniq_idx = itertools.count()
        self._alt_id_set: set[SolAltID] = set()
        self._sol_tx_list_dict: dict[str, list[tuple[SolTx, bool]]] = dict()

        self._base_tx_acct_set = NeonBaseTxAccountSet.default()

        self._ro_addr_list: tuple[SolPubKey, ...] = tuple()
        self._acct_meta_list: tuple[SolAccountMeta, ...] = tuple()
        self._emul_resp: EmulNeonCallResp | None = None

        self._skip_simple_strategy = False
        self._test_mode = False

    def init_neon_prog(self, evm_cfg: EvmConfigModel) -> Self:
        self._evm_step_cnt_per_iter = evm_cfg.evm_step_cnt
        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.version)
        return self

    @cached_property
    def req_id(self) -> dict:
        if isinstance(self._tx_request, ExecTxRequest):
            return dict(tx=self._tx_request.tx.tx_id)
        return dict(tx=self._tx_request.stuck_tx.tx_id, is_stuck=True)

    @property
    def cfg(self) -> Config:
        return self._cfg

    @property
    def sol_client(self) -> SolClient:
        return self._sol_client

    @property
    def core_api_client(self) -> CoreApiClient:
        return self._core_api_client

    @property
    def fee_client(self) -> AtlasFeeClient:
        return self._fee_client

    @property
    def stat_client(self) -> StatClient:
        return self._stat_client

    @property
    def db(self) -> IndexerDbClient:
        return self._db

    @cached_property
    def sol_tx_list_signer(self) -> SolTxListSigner:
        return OpTxListSigner(self.req_id, self.payer, self._op_client)

    @property
    def len_account_meta_list(self) -> int:
        return len(self._acct_meta_list)

    @property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return self._get_acct_key_list()

    @property
    def rw_account_key_list(self) -> tuple[SolPubKey, ...]:
        return self.neon_prog.rw_account_key_list

    @reset_cached_method
    def _get_acct_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple([SolPubKey.from_raw(meta.pubkey) for meta in self._acct_meta_list])

    @property
    def skip_simple_strategy(self) -> bool:
        return self._skip_simple_strategy

    def mark_skip_simple_strategy(self) -> None:
        self._skip_simple_strategy = True

    def set_tx_sol_address(self, base_tx_account_set: NeonBaseTxAccountSet) -> None:
        self._base_tx_acct_set = base_tx_account_set

    def set_holder_account(self, holder: HolderAccountModel) -> None:
        self._holder = holder

    def set_emulator_result(self, resp: EmulNeonCallResp) -> None:
        _LOG.debug("emulator result contains %d EVM steps, %d iterations", resp.evm_step_cnt, resp.iter_cnt)

        self._emul_resp = resp
        self._update_acct_meta_list()

        # reset calculated cache
        self._calc_total_evm_step_cnt.reset_cache(self)
        self._calc_total_iter_cnt.reset_cache(self)
        self._calc_wrap_iter_cnt.reset_cache(self)
        self._calc_resize_iter_cnt.reset_cache(self)

    def _update_acct_meta_list(self) -> None:
        # Get metas from the emulator
        acct_meta_dict: dict[SolPubKey, SolAccountMeta] = {
            SolPubKey.from_raw(m.pubkey): m
            for m in self._emul_resp.sol_account_meta_list
        }

        # Keep metas from the holder
        for key in self._holder.account_key_list:
            if key not in acct_meta_dict:
                acct_meta_dict[key] = SolAccountMeta(pubkey=key, is_signer=False, is_writable=True)

        acct_meta_list = tuple(sorted(acct_meta_dict.values(), key=lambda m: bytes(m.pubkey)))
        if acct_meta_list == self._acct_meta_list:
            _LOG.debug("emulator result contains the same %d accounts", len(acct_meta_list))
            return

        _LOG.debug(
            "emulator result contains %d accounts: %s",
            len(self._emul_resp.sol_account_meta_list),
            self._FmtAcctMeta(self._emul_resp.sol_account_meta_list),
        )
        _LOG.debug(
            "holder contains %d accounts, total %d accounts: %s",
            len(self._holder.account_key_list),
            len(acct_meta_list),
            self._FmtAcctMeta(acct_meta_list),
        )

        acct_meta_cnt = NeonProg.BaseAccountCnt + len(acct_meta_list)
        if acct_meta_cnt > self._cfg.max_tx_account_cnt:
            _LOG.warning(
                "account list is too long, %d > %d(limit)",
                acct_meta_cnt,
                self._cfg.max_tx_account_cnt,
            )
            if self._holder and self._holder.account_key_list:
                acct_meta_list = tuple([acct_meta_dict.get(key) for key in self._holder.account_key_list])
                _LOG.debug("use %d holder accounts", len(acct_meta_list))
            else:
                acct_meta_list = acct_meta_list[: self._cfg.max_tx_account_cnt]

        self._get_acct_key_list.reset_cache(self)
        self._acct_meta_list = acct_meta_list
        self._neon_prog.init_account_meta_list(acct_meta_list)
        self._test_neon_prog.init_account_meta_list(acct_meta_list)

    @property
    def is_started(self) -> bool:
        return self._holder.is_active

    @property
    def holder_block(self) -> CoreApiBlockModel:
        return self._holder.block

    @property
    def ro_address_list(self) -> tuple[SolPubKey, ...]:
        return self._ro_addr_list

    def set_ro_address_list(self, addr_list: Sequence[SolPubKey]) -> None:
        addr_set = set(addr_list).union(self._global_ro_addr_set)
        addr_list = tuple(addr_set)
        _LOG.debug("readonly accounts %s: %s", len(addr_list), addr_list)

        self._ro_addr_list = addr_list
        self._neon_prog.init_ro_address_list(addr_list)
        self._test_neon_prog.init_ro_address_list(addr_list)

    class _FmtAcctMeta:
        def __init__(self, acct_meta_list: Sequence[SolAccountMeta]) -> None:
            self._acct_meta_list = acct_meta_list

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
        prog.init_tx_sol_address(self._base_tx_acct_set)
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
    def tx_type(self) -> int:
        if self.is_stuck_tx:
            return self._holder.tx_type
        return self.neon_tx.tx_type

    @cached_property
    def max_fee_per_gas(self) -> int:
        assert self.tx_type == 2
        if self.is_stuck_tx:
            return self._holder.tx.max_fee_per_gas
        return self.neon_tx.max_fee_per_gas

    @cached_property
    def max_priority_fee_per_gas(self) -> int:
        assert self.tx_type == 2
        if self.is_stuck_tx:
            return self._holder.tx.max_priority_fee_per_gas
        return self.neon_tx.max_priority_fee_per_gas

    @cached_property
    def neon_tx(self) -> NeonTxModel:
        assert not self.is_stuck_tx
        return self._tx_request.tx.neon_tx

    @cached_property
    def holder_tx(self) -> CoreApiTxModel:
        if self.is_stuck_tx:
            return self._holder.tx
        return CoreApiTxModel.from_neon_tx(self.neon_tx, self.chain_id)

    @cached_property
    def neon_tx_hash(self) -> EthTxHash:
        if self.is_stuck_tx:
            return self._tx_request.stuck_tx.neon_tx_hash
        return self._tx_request.tx.neon_tx_hash

    @cached_property
    def has_chain_id(self) -> bool:
        if self.is_stuck_tx:
            assert self._holder
            return True

        return self._tx_request.tx.neon_tx.has_chain_id

    @cached_property
    def chain_id(self) -> int:
        if self.is_stuck_tx:
            return self._holder.chain_id
        return self._tx_request.tx.chain_id

    @cached_property
    def sender(self) -> NeonAccount:
        if self.is_stuck_tx:
            return self._holder.sender
        tx = self._tx_request.tx
        return NeonAccount.from_raw(tx.sender, tx.chain_id)

    @cached_property
    def receiver(self) -> NeonAccount:
        if self.is_stuck_tx:
            return self._holder.receiver
        tx = self._tx_request.tx
        return NeonAccount.from_raw(tx.receiver, tx.chain_id)

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
        assert self._emul_resp
        return self._emul_resp.evm_step_cnt

    @property
    def total_iter_cnt(self) -> int:
        return self._calc_total_iter_cnt()

    @reset_cached_method
    def _calc_total_iter_cnt(self) -> int:
        assert not self.is_stuck_tx
        assert self._emul_resp

        return max(self._emul_resp.iter_cnt, 1)

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
    def has_external_sol_call(self) -> bool:
        if self.is_stuck_tx:
            return False

        assert self._emul_resp
        return self._emul_resp.external_sol_call

    @property
    def has_holder_block(self) -> bool:
        assert self._emul_resp
        return self._emul_resp.is_block_used

    @property
    def alt_id_list(self) -> tuple[SolAltID, ...]:
        return tuple(self._alt_id_set)

    @property
    def stuck_alt_address_list(self) -> tuple[SolPubKey, ...]:
        assert self.is_stuck_tx
        return tuple(self._tx_request.stuck_tx.alt_address_list)

    def add_alt_id(self, alt_id: SolAltID) -> None:
        self._alt_id_set.add(alt_id)

    def good_sol_tx_cnt(self, name: str) -> int:
        cnt = 0
        if tx_list := self._sol_tx_list_dict.get(name, None):
            for _, is_success in tx_list:
                if is_success:
                    cnt += 1
        return cnt

    def pop_sol_tx_list(self, tx_name_list: tuple[str, ...]) -> tuple[SolTx, ...]:
        tx_list: list[SolTx] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_tx_list_dict.pop(tx_name, None):
                tx_list.extend([tx for tx, _ in tx_sublist])
        return tuple(tx_list)

    def add_sol_tx_list(self, tx_list: Sequence[tuple[SolTx, bool]]) -> None:
        for tx, is_success in tx_list:
            self._sol_tx_list_dict.setdefault(tx.name, list()).append((tx, is_success))

from __future__ import annotations

import dataclasses
import itertools
import logging
from typing import Sequence, ClassVar

from typing_extensions import Self

from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.neon.evm_log_decoder import NeonTxBlockInfo
from common.neon.neon_program import NeonProg, NeonBaseTxAccountSet
from common.neon_rpc.api import EmulNeonCallResp, HolderAccountModel, CoreApiTxModel, CoreApiBlockModel
from common.neon_rpc.transaction_list_sender import SolNeonTxListSender, SolNeonTxSendState
from common.solana.alt_program import SolAltID
from common.solana.instruction import SolAccountMeta
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.solana_rpc.transaction_list_sender import SolTxListSigner
from common.utils.cached import cached_property, cached_method, reset_cached_method
from common.utils.format import if_none
from .holder_validator import HolderAccountValidator
from .server_abc import ExecutorComponent, ExecutorServerAbc
from .skd_tree_parser import NeonSkdTreeParser
from .transaction_list_signer import OpTxListSigner
from ..base.ex_api import ExecTxRequest, CompleteStuckTxRequest, ExecTokenModel
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class NeonExecTxState:
    total_used_gas: int
    completed_evm_step_cnt: int
    completed_iter_cnt: int
    status: None | int
    tx_block: NeonTxBlockInfo

    _default: ClassVar[NeonExecTxState | None] = None

    @classmethod
    def default(cls) -> NeonExecTxState:
        if not cls._default:
            cls._default = NeonExecTxState(0, 0, 0, None, NeonTxBlockInfo.default())

        return cls._default

    @property
    def is_completed(self) -> bool:
        return self.status is not None

    @cached_property
    def holder_block(self) -> CoreApiBlockModel:
        return CoreApiBlockModel(timestamp=self.tx_block.timestamp, slot=self.tx_block.slot)

    @cached_property
    def slot(self) -> int:
        return self.tx_block.slot


class NeonExecTxCtx(ExecutorComponent):
    def __init__(
        self,
        server: ExecutorServerAbc,
        op_resource: OpResourceModel,
        tx_request: ExecTxRequest | CompleteStuckTxRequest,
        token: ExecTokenModel | None,
        skd_tree_parser: NeonSkdTreeParser | None,
    ) -> None:
        super().__init__(server)

        self._op_resource = op_resource
        self._tx_request = tx_request
        self._token = token

        self._uniq_idx = itertools.count()
        self._alt_id_set: set[SolAltID] = set()
        self._sol_neon_tx_state_list_dict: dict[str, list[SolNeonTxSendState]] = dict()

        self._base_tx_acct_set = NeonBaseTxAccountSet.default()
        self._acct_meta_list: Sequence[SolAccountMeta] = tuple()
        self._emul_resp: EmulNeonCallResp | None = None

        self._tx_exec_state = NeonExecTxState.default()

        self._skip_simple_strategy = False
        self._is_test_mode = False

        self._skd_tree_parser = skd_tree_parser

    @cached_property
    def _holder_addr(self) -> SolPubKey:
        if self.is_stuck_tx:
            return self._tx_request.stuck_tx.holder_address
        return self._op_resource.holder_address

    @cached_property
    def holder_validator(self) -> HolderAccountValidator:
        neon_tx_hash = self.neon_tx_hash
        base_tx_hash = self._skd_tree_parser.neon_tx_hash if self._skd_tree_parser else neon_tx_hash
        return HolderAccountValidator(self._server, base_tx_hash, neon_tx_hash, self._holder_addr, self.is_stuck_tx)

    @property
    def holder(self) -> HolderAccountModel:
        return self.holder_validator.holder_account

    @cached_property
    def sol_tx_list_signer(self) -> SolTxListSigner:
        return OpTxListSigner(self._tx_request.req_id, self.sol_payer, self._op_client)

    @cached_property
    def sol_tx_list_sender(self) -> SolNeonTxListSender:
        return SolNeonTxListSender(
            self._cfg,
            self._sol_client,
            self.sol_tx_list_signer,
            self._stat_client,
        )

    @cached_property
    def skd_tree_parser(self) -> NeonSkdTreeParser | None:
        return self._skd_tree_parser

    @property
    def len_account_meta_list(self) -> int:
        return len(self._acct_meta_list)

    @property
    def account_key_list(self) -> Sequence[SolPubKey]:
        return self._get_acct_key_list()

    @property
    def rw_account_key_list(self) -> Sequence[SolPubKey]:
        return self.neon_prog.rw_account_key_list

    @reset_cached_method
    def _get_acct_key_list(self) -> Sequence[SolPubKey]:
        if self._acct_meta_list:
            return tuple([SolPubKey.from_raw(meta.pubkey) for meta in self._acct_meta_list])
        elif not self._base_tx_acct_set.is_empty:
            return self._base_tx_acct_set.account_key_list
        return tuple()

    @property
    def skip_simple_strategy(self) -> bool:
        return self._skip_simple_strategy

    def mark_skip_simple_strategy(self) -> None:
        self._skip_simple_strategy = True

    def set_tx_sol_address(self, base_tx_account_set: NeonBaseTxAccountSet) -> None:
        self._base_tx_acct_set = base_tx_account_set

    def set_emulator_result(self, resp: EmulNeonCallResp) -> None:
        _LOG.debug("emulator result contains %d EVM steps, %d iterations", resp.evm_step_cnt, resp.iter_cnt)

        self._emul_resp = resp
        self._update_acct_meta_list()

        self.holder_validator.set_emul_step_cnt(resp.evm_step_cnt)

        # reset calculated cache
        self._calc_wrap_iter_cnt.reset_cache(self)
        self._calc_resize_iter_cnt.reset_cache(self)

    def _update_acct_meta_list(self) -> None:
        acct_meta_dict: dict[SolPubKey, SolAccountMeta]
        if not self._emul_resp.sol_account_meta_list:
            _LOG.warning("emulator result doesn't contain a account list")
            s = self._base_tx_acct_set
            acct_meta_dict = {
                s.sender: SolAccountMeta(s.sender, is_signer=False, is_writable=True),
                s.receiver: SolAccountMeta(s.sender, is_signer=False, is_writable=False),
                s.receiver_contract: SolAccountMeta(s.sender, is_signer=False, is_writable=True),
            }
        else:
            # Get metas from the emulator
            acct_meta_dict = {
                SolPubKey.from_raw(m.pubkey): m for m in self._emul_resp.sol_account_meta_list
            }

        # Keep metas from the holder in writable mode
        for key in self.holder.account_key_list:
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
        if self.holder.account_key_list:
            _LOG.debug(
                "holder contains %d accounts, total %d accounts: %s",
                len(self.holder.account_key_list),
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
            acct_meta_list = acct_meta_list[: self._cfg.max_tx_account_cnt]

        self._get_acct_key_list.reset_cache(self)
        self._acct_meta_list = acct_meta_list
        self._neon_prog.init_account_meta_list(acct_meta_list)
        self._test_neon_prog.init_account_meta_list(acct_meta_list)

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

    def test_mode(self) -> _TestMode:
        """This mode is used when a signer is unknown, or it is better to say - the signed isn't important.
        The signer is unknown on the testing stage,
        when we just need to check the structure of a Solana tx wo/ sending the Solana tx to Solana.
        """
        return self._TestMode(self)

    @property
    def is_test_mode(self) -> bool:
        return self._is_test_mode

    class _TestMode:
        def __init__(self, ctx: NeonExecTxCtx) -> None:
            self._ctx = ctx

        def __enter__(self) -> Self:
            self._ctx._is_test_mode = True
            return self

        def __exit__(self, exc_type, exc_val, exc_tb) -> Self:
            self._ctx._is_test_mode = False
            if exc_val:
                raise
            return self

    @property
    def neon_prog(self) -> NeonProg:
        if self._is_test_mode:
            return self._test_neon_prog
        return self._neon_prog

    @cached_property
    def _neon_prog(self) -> NeonProg:
        return self._new_neon_prog(self.sol_payer)

    @cached_property
    def _test_neon_prog(self) -> NeonProg:
        return self._new_neon_prog(SolSigner.fake().pubkey)

    def _new_neon_prog(self, payer: SolPubKey) -> NeonProg:
        prog = NeonProg(payer).init_holder_address(self._holder_addr)

        prog.init_token_address(self._op_resource.token_sol_address)

        rlp_tx = self._tx_request.tx.rlp_tx.to_bytes() if not self.is_stuck_tx else bytes()
        prog.init_neon_tx(self.neon_tx_hash, rlp_tx)
        prog.init_tx_sol_address(self._base_tx_acct_set)

        if self.is_scheduled_tx:
            prog.init_skd_tree_address(self._skd_tree_parser.address)

        return prog

    @cached_property
    def is_stuck_tx(self) -> bool:
        return isinstance(self._tx_request, CompleteStuckTxRequest)

    @cached_property
    def is_scheduled_tx(self) -> bool:
        if self._skd_tree_parser:
            return True
        elif self.is_stuck_tx:
            return self.holder.is_scheduled_tx
        return self._tx_request.tx.neon_tx.is_scheduled_tx

    @property
    def sol_payer(self) -> SolPubKey:
        return self._op_resource.owner

    @property
    def token(self) -> ExecTokenModel:
        return self._token

    @cached_property
    def holder_tx(self) -> CoreApiTxModel:
        if self.is_stuck_tx:
            return self.holder.tx
        return CoreApiTxModel.from_neon_tx(self._tx_request.tx.neon_tx)

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

    @cached_property
    def payer(self) -> NeonAddress:
        if self.is_scheduled_tx:
            return self._skd_tree_parser.payer
        return self.sender

    @property
    def has_payer_balance(self) -> bool:
        return self._base_tx_acct_set.payer_balance > 0

    @cached_property
    def sender(self) -> NeonAddress:
        if self.is_stuck_tx:
            return self.holder.sender

        tx = self._tx_request.tx
        return NeonAddress.from_raw(tx.sender, tx.chain_id)

    @cached_property
    def receiver(self) -> NeonAddress:
        if self.is_stuck_tx:
            return self.holder.receiver

        tx = self._tx_request.tx
        return NeonAddress.from_raw(tx.receiver, tx.chain_id)

    def next_uniq_idx(self) -> int:
        return next(self._uniq_idx)

    @property
    def total_evm_step_cnt(self) -> int:
        return max(self._emul_resp.evm_step_cnt - self.completed_evm_step_cnt, 0)

    @property
    def completed_evm_step_cnt(self) -> int:
        return self._tx_exec_state.completed_evm_step_cnt

    @property
    def completed_iter_cnt(self) -> int:
        return self._tx_exec_state.completed_iter_cnt

    @property
    def wrap_iter_cnt(self) -> int:
        return self._calc_wrap_iter_cnt()

    @reset_cached_method
    def _calc_wrap_iter_cnt(self) -> int:
        evm_step_cnt = self.neon_prog.EvmStepPerIter
        exec_iter_cnt = (self._emul_resp.evm_step_cnt + evm_step_cnt - 1) // evm_step_cnt
        iter_cnt = max(self._emul_resp.iter_cnt, 1) - exec_iter_cnt
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
        return self._emul_resp.external_sol_call

    @property
    def holder_block(self) -> CoreApiBlockModel:
        if not self._emul_resp:
            return CoreApiBlockModel.default()
        elif self._tx_exec_state.slot > if_none(self.holder.block.slot, 0):
            return self._tx_exec_state.holder_block
        return self.holder.block

    def set_tx_exec_state(self, state: NeonExecTxState) -> None:
        self._tx_exec_state = state

    def reset_tx_exec_state(self) -> None:
        self._tx_exec_state = NeonExecTxState.default()

    @property
    def is_completed_tx(self) -> bool:
        return self._tx_exec_state.is_completed

    @property
    def alt_id_list(self) -> Sequence[SolAltID]:
        return tuple(self._alt_id_set)

    @property
    def stuck_alt_address_list(self) -> Sequence[SolPubKey]:
        assert self.is_stuck_tx
        return tuple(self._tx_request.stuck_tx.alt_address_list)

    def add_alt_id(self, alt_id: SolAltID) -> None:
        self._alt_id_set.add(alt_id)

    def good_sol_tx_cnt(self, tx_name_list: str | Sequence[str]) -> int:
        if isinstance(tx_name_list, str):
            tx_name_list = tuple([tx_name_list])

        cnt = 0
        for tx_name in tx_name_list:
            if tx_state_list := self._sol_neon_tx_state_list_dict.get(tx_name, None):
                for tx_state in tx_state_list:
                    if tx_state.status == tx_state.status.GoodReceipt:
                        cnt += 1
        return cnt

    def get_sol_tx_state_list(self, tx_name_list: Sequence[str]) -> Sequence[SolNeonTxSendState]:
        tx_list: list[SolNeonTxSendState] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_neon_tx_state_list_dict.get(tx_name, None):
                tx_list.extend(tx_sublist)
        return tuple(tx_list)

    def pop_sol_tx_list(self, tx_name_list: Sequence[str]) -> Sequence[SolTx]:
        tx_list: list[SolTx] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_neon_tx_state_list_dict.pop(tx_name, None):
                tx_list.extend([tx_state.tx for tx_state in tx_sublist])
        return tuple(tx_list)

    def add_sol_tx_state_list(self, tx_state_list: Sequence[SolNeonTxSendState]) -> None:
        for tx_state in tx_state_list:
            self._sol_neon_tx_state_list_dict.setdefault(tx_state.name, list()).append(tx_state)

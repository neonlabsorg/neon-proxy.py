from __future__ import annotations

import dataclasses
import logging
from contextlib import contextmanager
from typing import Sequence, ClassVar, Self, Generator, Final

from common.ethereum.hash import EthTxHash
from common.neon.address import NeonAddress
from common.neon.cu_cost_packed import CuCostPktData
from common.neon.evm_log_decoder import NeonTxBlockInfo, NeonTxLogReturnInfo
from common.neon.neon_program import NeonProg, NeonBaseTxAccountSet
from common.neon.transaction_model import NeonSkdTxStatus
from common.neon_rpc.api import EmulNeonCallResp, HolderAccountModel, CoreApiTxModel, CoreApiBlockModel
from common.neon_rpc.errors import SolNeonSkdTxWrongStateError
from common.neon_rpc.transaction_list_sender import SolNeonTxListSender, SolNeonTxSendState
from common.solana.alt_info import SolAltInfo
from common.solana.alt_program import SolAltID
from common.solana.cb_program import SolCbCfg, SolCbProg
from common.solana.instruction import SolAccountMeta, SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.transaction import SolTx
from common.utils.cached import cached_property, cached_method, reset_cached_method
from .holder_validator import HolderAccountValidator
from .server_abc import ExecutorComponent, ExecutorServerAbc
from .skd_tree_parser import NeonSkdTreeParser
from .transaction_list_signer import OpTxListSigner
from ..base.ex_api import ExecTxRequest, CompleteStuckTxRequest, ExecTokenModel
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class NeonExecTxState:
    gas_used: int
    evm_step_cnt: int
    iter_cnt: int
    resize_iter_cnt: int
    tx_return: NeonTxLogReturnInfo
    tx_block: NeonTxBlockInfo

    _Default: ClassVar[NeonExecTxState | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._Default:
            cls._Default = NeonExecTxState(0, 0, 0, 0, NeonTxLogReturnInfo.default(), NeonTxBlockInfo.default())

        return cls._Default

    @classmethod
    def from_tx_return(cls, tx_return: NeonTxLogReturnInfo) -> Self:
        return cls(0, 0, 0, 0, tx_return, NeonTxBlockInfo.default())

    @property
    def is_completed(self) -> bool:
        return not self.tx_return.is_empty

    @cached_property
    def holder_block(self) -> CoreApiBlockModel:
        return CoreApiBlockModel(timestamp=self.tx_block.timestamp, slot=self.tx_block.slot)

    @cached_property
    def slot(self) -> int:
        return self.tx_block.slot


class NeonExecTxCtx(ExecutorComponent):
    _OpResPct: Final[int] = 2
    _EmulTxPct: Final[int] = 10
    _PrepareTxPct: Final[int] = 20
    _TotalExecPct: Final[int] = 100 - _PrepareTxPct
    _MaxExecPct: Final[int] = 95  # 100% is on complete tx in mempool

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

        self._alt_id_set: set[SolAltID] = set()
        self._sol_neon_tx_state_list_dict: dict[str, list[SolNeonTxSendState]] = dict()

        self._base_tx_acct_set = NeonBaseTxAccountSet.default()
        self._acct_meta_list: Sequence[SolAccountMeta] = tuple()
        self._emul_resp: EmulNeonCallResp | None = None

        self._is_prep_completed = False
        self._tx_exec_pct = 0
        self._tx_exec_state = NeonExecTxState.default()

        self._is_sol_tx_sender_locked = False
        self._skip_simple_strategy = False
        self._is_test_mode = False

        self._skd_tree_parser = skd_tree_parser

    @property
    def is_started_tx(self) -> bool:
        return self.gas_used > 0

    @cached_property
    def holder_validator(self) -> HolderAccountValidator:
        neon_tx_hash: Final = self.neon_tx_hash
        return HolderAccountValidator(self._server, neon_tx_hash, self._holder_addr, self._is_stuck_tx)

    @cached_property
    def holder_address(self) -> SolPubKey:
        return self._holder_addr

    @cached_property
    def max_sol_priority_fee(self) -> int:
        # if the Proxy accepts fee less transactions, it pays the maximum REQUIRED cu-price
        if self.holder_tx.is_fee_less:
            return SolCbProg.MaxPriorityFee

        # get cu-price from the gas-limit
        pkt: Final = CuCostPktData.unpack(self.holder_tx.gas_limit)

        # get additional cu-price from the gas-price difference
        profitable_gas_price: Final = self.token.profitable_gas_price
        tx_gas_price: Final = self.holder_tx.effective_gas_price
        if (gas_price_diff := tx_gas_price - profitable_gas_price) <= 0:
            return pkt.priority_fee

        priority_fee_from_gas_price: Final = NeonProg.BaseGas * gas_price_diff // profitable_gas_price
        return pkt.priority_fee + priority_fee_from_gas_price

    @cached_property
    def skd_tree_parser(self) -> NeonSkdTreeParser | None:
        return self._skd_tree_parser

    async def get_skd_tx_status(self) -> NeonSkdTxStatus:
        assert self.is_scheduled_tx
        status = await self._skd_tree_parser.get_neon_skd_status(self.skd_tx_idx)
        if status in (NeonSkdTxStatus.NotStarted, NeonSkdTxStatus.Destroyed):
            raise SolNeonSkdTxWrongStateError(status)
        return status

    @property
    def len_account_meta_list(self) -> int:
        return len(self._acct_meta_list)

    @property
    def account_key_list(self) -> Sequence[SolPubKey]:
        return self._get_acct_key_list()

    @property
    def skip_simple_strategy(self) -> bool:
        return self.is_started_tx or self._skip_simple_strategy

    async def send_sol_tx(
        self,
        ix_list: SolTxIx | Sequence[SolTxIx],
        /,
        cb_cfg: SolCbCfg | None = None,
        alt_list: Sequence[SolAltInfo] = tuple(),
    ) -> bool:
        with self._lock_sol_tx_list_sender() as tx_list_sender:
            return await tx_list_sender.send_tx(ix_list, cb_cfg=cb_cfg, alt_list=alt_list)

    async def send_sol_tx_list(
        self,
        ix_list: SolTxIx | Sequence[SolTxIx],
        /,
        cb_cfg: SolCbCfg | None = None,
        alt_list: Sequence[SolAltInfo] = tuple(),
    ) -> bool:
        with self._lock_sol_tx_list_sender() as tx_list_sender:
            return await tx_list_sender.send_tx_list(ix_list, cb_cfg=cb_cfg, alt_list=alt_list)

    async def recheck_sol_tx_list(self, tx_name_list: str | Sequence[str]) -> bool:
        if not (tx_list := self._pop_sol_tx_list(tx_name_list)):
            return False

        with self._lock_sol_tx_list_sender() as tx_list_sender:
            return await tx_list_sender.recheck(tx_list)

    def mark_skip_simple_strategy(self) -> None:
        self._skip_simple_strategy = True

    def set_tx_sol_address(self, base_tx_account_set: NeonBaseTxAccountSet) -> None:
        self._base_tx_acct_set = base_tx_account_set

    async def set_emulator_result(self, resp: EmulNeonCallResp) -> None:
        _LOG.debug("emulator result contains %d EVM steps, %d iterations", resp.evm_step_cnt, resp.iter_cnt)

        self._emul_resp = resp
        self._update_acct_meta_list()

        await self._notify_mp_status()

    @contextmanager
    def test_mode(self) -> Generator[Self, None, None]:
        """
        This mode is used when a signer is unknown, or it is better to say - the signed isn't important.
        The signer is unknown at the testing stage,
        when we just need to check the structure of a Solana tx wo/ sending the Solana tx to Solana.
        """
        assert not self._is_test_mode
        try:
            self._is_test_mode = True
            yield self
        finally:
            self._is_test_mode = False

    @property
    def is_test_mode(self) -> bool:
        return self._is_test_mode

    @property
    def neon_prog(self) -> NeonProg:
        if self._is_test_mode:
            return self._test_neon_prog
        return self._neon_prog

    @cached_property
    def is_scheduled_tx(self) -> bool:
        if self._skd_tree_parser:
            return True
        elif self._is_stuck_tx:
            return self._holder.is_scheduled_tx
        return self._tx_request.tx.neon_tx.is_scheduled_tx

    @cached_property
    def is_root_tx(self) -> bool:
        return self._root_neon_tx_hash == self.neon_tx_hash

    @property
    def sol_payer(self) -> SolPubKey:
        return self._op_resource.owner

    @property
    def token(self) -> ExecTokenModel:
        return self._token

    @cached_property
    def holder_tx(self) -> CoreApiTxModel:
        if self._is_stuck_tx:
            return self._holder.tx
        return CoreApiTxModel.from_neon_tx(self._tx_request.tx.neon_tx)

    @cached_property
    def skd_tx_idx(self) -> int:
        assert self.is_scheduled_tx
        return self.holder_tx.index

    @cached_property
    def neon_tx_hash(self) -> EthTxHash:
        if self._is_stuck_tx:
            return self._tx_request.stuck_tx.neon_tx_hash
        return self._tx_request.tx.neon_tx_hash

    @cached_property
    def has_chain_id(self) -> bool:
        if self._is_stuck_tx:
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
        if self._is_stuck_tx:
            return self._holder.sender

        tx = self._tx_request.tx
        return NeonAddress.from_raw(tx.sender, tx.chain_id)

    @cached_property
    def receiver(self) -> NeonAddress:
        if self._is_stuck_tx:
            return self._holder.receiver

        tx = self._tx_request.tx
        return NeonAddress.from_raw(tx.receiver, tx.chain_id)

    @property
    def gas_used(self) -> int:
        return max(self._tx_exec_state.gas_used, self._holder.gas_used)

    @property
    def completed_evm_step_cnt(self) -> int:
        if self._holder.gas_used > self._tx_exec_state.gas_used:
            return self._holder.evm_step_cnt
        return self._tx_exec_state.evm_step_cnt

    @property
    def total_evm_step_cnt(self) -> int:
        return max(self._emul_resp.evm_step_cnt - self.completed_evm_step_cnt, 0)

    @property
    def completed_resize_iter_cnt(self) -> int:
        return self._tx_exec_state.resize_iter_cnt

    @property
    def completed_iter_cnt(self) -> int:
        return self._tx_exec_state.iter_cnt

    @property
    def resize_iter_cnt(self) -> int:
        return self._emul_resp.resize_iter_cnt

    @property
    def has_sol_call(self) -> bool:
        return self._emul_resp.external_sol_call

    async def mark_complete_prepare(self) -> None:
        self._is_prep_completed = True
        await self._notify_mp_status()

    async def set_tx_exec_state(self, state: NeonExecTxState) -> None:
        self._tx_exec_state = state
        await self._notify_mp_status()

    def reset_tx_exec_state(self) -> None:
        self._tx_exec_state = NeonExecTxState.default()

    async def is_finalized_tx(self) -> bool:
        if self._tx_exec_state.is_completed:
            return True

        # better to check the status in a tree, it has a smaller size and can be changed from different holders
        if self.is_scheduled_tx:
            status = await self.get_skd_tx_status()
            if status in (NeonSkdTxStatus.ToSkip, NeonSkdTxStatus.ToStart):
                return False
            elif status != NeonSkdTxStatus.InProgress:
                return True

        return await self.holder_validator.is_finalized()

    @property
    def alt_id_list(self) -> Sequence[SolAltID]:
        return tuple(self._alt_id_set)

    def pop_alt_id_list(self) -> Sequence[SolAltID]:
        alt_id_list, self._alt_id_set = self.alt_id_list, set()
        return alt_id_list

    @property
    def stuck_alt_address_list(self) -> Sequence[SolPubKey]:
        assert self._is_stuck_tx
        return tuple(self._tx_request.stuck_tx.alt_address_list)

    def add_alt_id(self, alt_id: SolAltID | Sequence[SolAltID]) -> None:
        if not alt_id:
            return
        elif isinstance(alt_id, SolAltID):
            alt_id = (alt_id,)
        self._alt_id_set.update(alt_id)

    def get_sol_tx_state_list(self, tx_name_list: str | Sequence[str]) -> Sequence[SolNeonTxSendState]:
        if isinstance(tx_name_list, str):
            tx_name_list = tuple([tx_name_list])

        tx_list: list[SolNeonTxSendState] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_neon_tx_state_list_dict.get(tx_name, None):
                tx_list.extend(tx_sublist)
        return tuple(tx_list)

    # protected:
    #
    @contextmanager
    def _lock_sol_tx_list_sender(self) -> Generator[SolNeonTxListSender, None]:
        assert not self._is_sol_tx_sender_locked

        tx_list_sender = self._sol_tx_list_sender
        tx_list_sender.clear()

        try:
            self._is_sol_tx_sender_locked = True
            yield tx_list_sender
        finally:
            self._is_sol_tx_sender_locked = False
            tx_state_list = tx_list_sender.success_tx_state_list
            self._store_sol_tx_state_list(tx_state_list)

    @cached_property
    def _sol_tx_list_sender(self) -> SolNeonTxListSender:
        sol_tx_list_signer = OpTxListSigner(self._tx_request.req_id, self.sol_payer, self._op_client)

        return SolNeonTxListSender(
            self._cfg,
            self._sol_client,
            sol_tx_list_signer,
            self._stat_client,
            self._core_api_client,
            self._cu_price_client,
        )

    def _store_sol_tx_state_list(self, tx_state_list: Sequence[SolNeonTxSendState]) -> None:
        for tx_state in tx_state_list:
            self._sol_neon_tx_state_list_dict.setdefault(tx_state.name, list()).append(tx_state)

    def _pop_sol_tx_list(self, tx_name_list: str | Sequence[str]) -> Sequence[SolTx]:
        if isinstance(tx_name_list, str):
            tx_name_list = tuple([tx_name_list])

        tx_list: list[SolTx] = list()
        for tx_name in tx_name_list:
            if tx_sublist := self._sol_neon_tx_state_list_dict.pop(tx_name, None):
                tx_list.extend([tx_state.tx for tx_state in tx_sublist])
        return tuple(tx_list)

    @cached_property
    def _is_stuck_tx(self) -> bool:
        return isinstance(self._tx_request, CompleteStuckTxRequest)

    @cached_property
    def _holder_addr(self) -> SolPubKey:
        if self._is_stuck_tx:
            return self._tx_request.stuck_tx.holder_address
        return self._op_resource.holder_address

    @property
    def _holder(self) -> HolderAccountModel:
        return self.holder_validator.holder_account

    @cached_property
    def _root_neon_tx_hash(self) -> EthTxHash:
        return self._skd_tree_parser.root_neon_tx_hash if self.is_scheduled_tx else self.neon_tx_hash

    @cached_property
    def _neon_prog(self) -> NeonProg:
        return self._create_neon_prog(self.sol_payer)

    @cached_property
    def _test_neon_prog(self) -> NeonProg:
        return self._create_neon_prog(SolSigner.fake().pubkey)

    def _create_neon_prog(self, payer: SolPubKey) -> NeonProg:
        prog = NeonProg(payer).init_holder_address(self._holder_addr)

        prog.init_token_address(self._op_resource.token_sol_address)

        rlp_tx = self._tx_request.tx.rlp_tx.to_bytes() if not self._is_stuck_tx else bytes()
        prog.init_neon_tx(self.neon_tx_hash, rlp_tx)
        prog.init_tx_sol_address(self._base_tx_acct_set)

        if self.is_scheduled_tx:
            prog.init_skd_tree_address(self._skd_tree_parser.address)

        return prog

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
            acct_meta_dict = {SolPubKey.from_raw(m.pubkey): m for m in self._emul_resp.sol_account_meta_list}

        # Keep metas from the holder in writable mode
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
            _FmtAcctMeta(self._emul_resp.sol_account_meta_list),
        )
        if self._holder.account_key_list:
            _LOG.debug(
                "holder contains %d accounts, total %d accounts: %s",
                len(self._holder.account_key_list),
                len(acct_meta_list),
                _FmtAcctMeta(acct_meta_list),
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

    @reset_cached_method
    def _get_acct_key_list(self) -> Sequence[SolPubKey]:
        if self._acct_meta_list:
            return tuple([SolPubKey.from_raw(meta.pubkey) for meta in self._acct_meta_list])
        elif not self._base_tx_acct_set.is_empty:
            return self._base_tx_acct_set.account_key_list
        return tuple()

    async def _notify_mp_status(self) -> None:
        if self._is_stuck_tx:
            return

        if self._tx_exec_state.is_completed:
            tx_exec_pct = self._MaxExecPct
        elif self.gas_used or self.completed_evm_step_cnt:
            gas_pct = int(self._TotalExecPct * (self.gas_used / self.holder_tx.gas_limit))
            step_pct = int(self._TotalExecPct * (self.completed_evm_step_cnt / self._emul_resp.evm_step_cnt))
            tx_exec_pct = min(max(gas_pct, step_pct) + self._PrepareTxPct, self._MaxExecPct)
        elif self._is_prep_completed:
            tx_exec_pct = self._PrepareTxPct
        elif self._emul_resp:
            tx_exec_pct = self._EmulTxPct
        else:
            tx_exec_pct = self._OpResPct

        if tx_exec_pct == self._tx_exec_pct:
            return

        self._tx_exec_pct = tx_exec_pct
        await self._mp_client.notify_exec_tx_status(self._root_neon_tx_hash, self.neon_tx_hash, self._tx_exec_pct)

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

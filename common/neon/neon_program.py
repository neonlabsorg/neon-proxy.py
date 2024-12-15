from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, Final, Sequence

from typing_extensions import Self

from .address import NeonAddress
from ..config.constants import NEON_EVM_PROGRAM_ID, NEON_PROXY_VER
from ..ethereum.errors import EthError
from ..ethereum.hash import EthTxHash
from ..solana.instruction import SolTxIx, SolAccountMeta
from ..solana.pubkey import SolPubKey
from ..solana.sys_program import SolSysProg
from ..utils.cached import reset_cached_method, cached_property

_LOG = logging.getLogger(__name__)


class NeonEvmProtocol(IntEnum):
    Unknown = -1
    v1004 = 1004  # 1.4  -> 1.004
    v1013 = 1013  # 1.13 -> 1.013
    v1017 = 1017  # 1.17 -> 1.017


# fmt: off
SUPPORTED_VERSION_SET = frozenset(
    (
        NeonEvmProtocol.v1017,
    )
)
# fmt: on


# fmt: off
class NeonEvmIxCode(IntEnum):
    Unknown = -1
    CollectTreasure = 0x1e                     # 30

    HolderCreate = 0x24                        # 36
    HolderDelete = 0x25                        # 37
    HolderWrite = 0x26                         # 38

    CreateAccountBalance = 0x30                # 48
    Deposit = 0x31                             # 49

    TxExecFromData = 0x3d                      # 61
    TxExecFromAccount = 0x33                   # 51
    TxStepFromData = 0x34                      # 52
    TxStepFromAccount = 0x35                   # 53
    TxStepFromAccountNoChainId = 0x36          # 54

    TxExecFromDataSolanaCall = 0x3e            # 62
    TxExecFromAccountSolanaCall = 0x39         # 57

    CancelWithHash = 0x37                      # 55

    CreateOperatorBalance = 0x3a               # 58
    DeleteOperatorBalance = 0x3b               # 59
    WithdrawOperatorBalance = 0x3c             # 60

    SkdTxStartFromAccount = 0x46               # 70
    SkdTxStartFromData = 0x47                  # 71
    SkdTxFinish = 0x49                         # 73
    SkdTxCreate = 0x4a                         # 74
    SkdTxCreateMultiple = 0x4b                 # 75
    SkdTreeDestroy = 0x4c                        # 76
    SkdTxSkipFromAccount = 0x4d                # 77
    SkdTxSkipFromData = 0x4e                   # 78

    OldTxExecFromDataV1013 = 0x32              # 50
    OldTxExecFromDataSolanaCallV1013 = 0x38    # 56

    OldDepositV1004 = 0x27                     # 39
    OldCreateAccountV1004 = 0x28               # 40

    OldTxExecFromDataV1004 = 0x1f              # 31
    OldTxExecFromAccountV1004 = 0x2a           # 42
    OldTxStepFromDataV1004 = 0x20              # 32
    OldTxStepFromAccountV1004 = 0x21           # 33
    OldTxStepFromAccountNoChainIdV1004 = 0x22  # 34

    OldCancelWithHashV1004 = 0x23              # 35

    @classmethod
    def from_raw(cls, raw: int) -> Self:
        try:
            return cls(raw)
        except (BaseException,):
            return cls.Unknown
# fmt: on


class NeonIxMode(IntEnum):
    Unknown = 0

    Readable = 1
    Writable = 2
    FullWritable = 3

    BaseTx = 4

    Default = Readable


@dataclass(frozen=True)
class NeonBaseTxAccountSet:
    payer: SolPubKey
    sender: SolPubKey
    receiver: SolPubKey
    receiver_contract: SolPubKey

    _default: ClassVar[NeonBaseTxAccountSet | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = cls(
                payer=SolPubKey.default(),
                sender=SolPubKey.default(),
                receiver=SolPubKey.default(),
                receiver_contract=SolPubKey.default(),
            )
        return cls._default

    @property
    def is_empty(self) -> bool:
        return self.sender.is_empty


@dataclass(frozen=True)
class NeonProgCfg:
    treasury_pool_cnt: int
    treasury_pool_seed: bytes
    treasury_payment: int
    evm_version: str

    @cached_property
    def protocol_version(self) -> NeonEvmProtocol:
        try:
            ver_part_list = self.evm_version.split(".")
            if len(ver_part_list) != 3:
                _LOG.error("wrong format of NeonEVM version %s", self.evm_version)
                return NeonEvmProtocol.Unknown

            major, minor, build = ver_part_list
            protocol = major + str(minor).rjust(3, "0")
            return NeonEvmProtocol(int(protocol))

        except (BaseException,):
            _LOG.error("wrong format of NeonEVM version %s", self.evm_version)
            return NeonEvmProtocol.Unknown


class NeonProg:
    _treasury_pool_cnt: ClassVar[int | None] = None
    _treasury_pool_seed: ClassVar[bytes | None] = None
    _protocol_version: ClassVar[NeonEvmProtocol] = NeonEvmProtocol.Unknown
    _evm_version: ClassVar[str] = "0.0.0"
    _deposit_seed: Final[bytes] = b"Deposit"

    ID: ClassVar[SolPubKey] = NEON_EVM_PROGRAM_ID
    DepositAddress: ClassVar[SolPubKey] = SolPubKey.find_program_address(tuple([_deposit_seed]), ID)[0]
    #
    SignatureGas: Final[int] = 5_000
    TreasuryGas: ClassVar[int] = 0
    BaseGas: ClassVar[int] = SignatureGas + 0

    # Holder IX CUs limit
    CuLimitHolderWrite: Final[int] = 25_000
    CuLimitHolderCreate: Final[int] = 7_500
    CuLimitHolderDestroy: Final[int] = 7_500
    # Operator balance CUs limit
    CuLimitOpCreateBalance: Final[int] = 150_000
    # Tree account CUs limit
    CuLimitSkdTreeAccountDestroy: Final[int] = 200_000

    # The notation is as follows:
    #   The first, without +, goes required accounts for the Neon instruction.
    #   Then, with + prefix, follows accounts that aren't listed in the Neon instruction, but are a part of Solana
    #   transaction account list.
    # 1. holder
    # 2. payer
    # 3. treasury-pool-address
    # 4. payer-token-address
    # 5. SolSysProg.ID
    # +6: NeonProg.ID
    # +7: CbProg.ID
    BaseAccountCnt: Final[int] = 7

    def __init__(self, payer: SolPubKey) -> None:
        assert self._treasury_pool_cnt is not None, "NeonProg should be initialized: NeonProg.init_prog"

        self._payer = payer
        self._token_sol_addr = SolPubKey.default()
        self._holder_addr = SolPubKey.default()
        self._acct_meta_list: list[SolAccountMeta] = list()
        self._addr_set: set[SolPubKey] = set()
        self._ro_addr_set: set[SolPubKey] = set()
        self._rlp_tx = bytes()
        self._neon_tx_hash = EthTxHash.default()
        self._base_tx_acct_set = NeonBaseTxAccountSet.default()
        self._treasury_pool_index_buf = bytes()
        self._treasury_pool_addr = SolPubKey.default()
        self._skd_tree_addr = SolPubKey.default()

    @classmethod
    def init_prog(cls, cfg: NeonProgCfg) -> None:
        cls._treasury_pool_cnt = cfg.treasury_pool_cnt
        cls._treasury_pool_seed = cfg.treasury_pool_seed
        cls._evm_version = cfg.evm_version
        cls._protocol_version = cfg.protocol_version

        cls.TreasuryGas = cfg.treasury_payment
        cls.BaseGas = cls.SignatureGas + cfg.treasury_payment

    @classmethod
    def is_init(cls) -> bool:
        return cls._treasury_pool_cnt is not None

    @classmethod
    def validate_protocol(cls) -> None:
        if cls._protocol_version not in SUPPORTED_VERSION_SET:
            raise EthError(f"Neon-Proxy {NEON_PROXY_VER} is not compatible with Neon-EVM v{cls._evm_version}")

    def init_token_address(self, token_sol_address: SolPubKey) -> Self:
        self._token_sol_addr = token_sol_address
        return self

    def init_holder_address(self, holder_address: SolPubKey) -> Self:
        self._holder_addr = holder_address
        return self

    def init_skd_tree_address(self, skd_tree_address: SolPubKey) -> Self:
        self._skd_tree_addr = skd_tree_address
        return self

    def init_neon_tx(self, neon_tx_hash: EthTxHash, rlp_tx: bytes) -> Self:
        self._rlp_tx = rlp_tx
        self._neon_tx_hash = neon_tx_hash

        base_index = int().from_bytes(self._neon_tx_hash.to_bytes()[:4], "little")
        _, index_buf, addr = self.calc_treasury_address(base_index)

        self._treasury_pool_index_buf = index_buf
        self._treasury_pool_addr = addr
        return self

    @classmethod
    def calc_treasury_address(cls, base_index: int) -> tuple[int, bytes, SolPubKey]:
        assert cls._treasury_pool_cnt is not None, "NeonProg should be initialized: NeonProg.init_prog"
        index = base_index % cls._treasury_pool_cnt
        index_buf = index.to_bytes(4, "little")

        addr, _ = SolPubKey.find_program_address(
            seed_list=(
                cls._treasury_pool_seed,
                index_buf,
            ),
            prog_id=cls.ID,
        )

        return index, index_buf, addr

    def init_tx_sol_address(self, base_tx_account_set: NeonBaseTxAccountSet) -> Self:
        _LOG.debug(
            "set payer solana address %s, "
            "set sender solana address %s, "
            "receiver solana address %s, "
            "receiver contract address %s",
            base_tx_account_set.payer,
            base_tx_account_set.sender,
            base_tx_account_set.receiver,
            base_tx_account_set.receiver_contract,
        )
        self._base_tx_acct_set = base_tx_account_set
        return self

    def init_account_meta_list(self, account_meta_list: Sequence[SolAccountMeta]) -> Self:
        self._acct_meta_list = list(account_meta_list)
        self._addr_set = set(map(lambda x: SolPubKey.from_raw(x.pubkey), account_meta_list))
        self._ro_addr_set.clear()
        self._get_ro_acct_meta_list.reset_cache(self)
        self._get_rw_acct_meta_list.reset_cache(self)
        self._get_rw_acct_key_list.reset_cache(self)
        self._get_base_tx_acct_meta_list.reset_cache(self)
        return self

    def init_ro_address_list(self, address_list: Sequence[SolPubKey]) -> Self:
        self._ro_addr_set = set(address_list)

        self._get_ro_acct_meta_list.reset_cache(self)
        self._get_rw_acct_meta_list.reset_cache(self)
        self._get_base_tx_acct_meta_list.reset_cache(self)

        for idx, acct in enumerate(self._acct_meta_list):
            if SolPubKey.from_raw(acct.pubkey) in self._ro_addr_set:
                self._acct_meta_list[idx] = SolAccountMeta(
                    acct.pubkey,
                    acct.is_signer,
                    is_writable=False,
                )

        return self

    @property
    def holder_msg(self) -> bytes:
        assert self._rlp_tx is not None
        return self._rlp_tx

    @property
    def rw_account_key_list(self) -> Sequence[SolPubKey]:
        return self._get_rw_acct_key_list()

    def make_delete_holder_ix(self) -> SolTxIx:
        self.validate_protocol()

        _LOG.debug("deleteHolderIx %s with the refund to the account %s", self._holder_addr, self._payer)
        ix_data = NeonEvmIxCode.HolderDelete.value.to_bytes(1, byteorder="little")
        return SolTxIx(
            accounts=(
                SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            ),
            program_id=self.ID,
            data=ix_data,
        )

    def make_create_holder_ix(self, seed: str) -> SolTxIx:
        self.validate_protocol()

        _LOG.debug("createHolderIx %s by the payer account %s", self._holder_addr, self._payer)

        seed = bytes(seed, "utf-8")
        ix_data_list = (
            NeonEvmIxCode.HolderCreate.value.to_bytes(1, byteorder="little"),
            len(seed).to_bytes(8, "little"),
            seed,
        )
        return SolTxIx(
            accounts=(
                SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            ),
            program_id=self.ID,
            data=bytes().join(ix_data_list),
        )

    def make_create_neon_account_ix(
        self,
        neon_address: NeonAddress,
        sol_address: SolPubKey,
        contract_sol_address: SolPubKey,
    ) -> SolTxIx:
        self.validate_protocol()

        _LOG.debug(
            "Create neon address: %s, solana address: %s, contract solana address: %s",
            neon_address,
            sol_address,
            contract_sol_address,
        )

        ix_data_list = (
            NeonEvmIxCode.CreateAccountBalance.value.to_bytes(1, byteorder="little"),
            neon_address.to_bytes(),
            neon_address.chain_id.to_bytes(8, byteorder="little"),
        )

        return SolTxIx(
            program_id=self.ID,
            data=bytes().join(ix_data_list),
            accounts=(
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SolSysProg.ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=sol_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=contract_sol_address, is_signer=False, is_writable=True),
            ),
        )

    def make_create_operator_balance_ix(self, neon_address: NeonAddress) -> SolTxIx:
        self.validate_protocol()

        _LOG.debug("Create operator token account: %s, solana address: %s", neon_address, self._token_sol_addr)

        ix_data_list = (
            NeonEvmIxCode.CreateOperatorBalance.value.to_bytes(1, byteorder="little"),
            neon_address.eth_address.to_bytes(),
            neon_address.chain_id.to_bytes(8, byteorder="little"),
        )

        return SolTxIx(
            program_id=self.ID,
            data=bytes().join(ix_data_list),
            accounts=(
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SolSysProg.ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
            ),
        )

    def make_delete_operator_balance_ix(self) -> SolTxIx:
        _LOG.debug("Delete operator token account, solana address: %s", self._token_sol_addr)

        ix_data = NeonEvmIxCode.DeleteOperatorBalance.value.to_bytes(1, byteorder="little")

        return SolTxIx(
            program_id=self.ID,
            data=ix_data,
            accounts=(
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
            ),
        )

    def make_withdraw_operator_balance_ix(self, neon_token_address: SolPubKey) -> SolTxIx:
        _LOG.debug("Withdraw from operator balance %s to neon balance %s", self._token_sol_addr, neon_token_address)

        ix_data = NeonEvmIxCode.WithdrawOperatorBalance.value.to_bytes(1, byteorder="little")

        return SolTxIx(
            program_id=self.ID,
            data=ix_data,
            accounts=(
                SolAccountMeta(pubkey=SolSysProg.ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=neon_token_address, is_signer=False, is_writable=True),
            ),
        )

    def make_write_ix(self, offset: int, data: bytes) -> SolTxIx:
        self.validate_protocol()

        ix_data_list = (
            NeonEvmIxCode.HolderWrite.value.to_bytes(1, byteorder="little"),
            self._neon_tx_hash.to_bytes(),
            offset.to_bytes(8, byteorder="little"),
            data,
        )
        return SolTxIx(
            program_id=self.ID,
            data=bytes().join(ix_data_list),
            accounts=(
                SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=False),
            ),
        )

    def make_tx_exec_from_data_ix(self) -> SolTxIx:
        return self._make_tx_exec_from_data_ix(NeonEvmIxCode.TxExecFromData)

    def make_tx_exec_from_data_solana_call_ix(self) -> SolTxIx:
        return self._make_tx_exec_from_data_ix(NeonEvmIxCode.TxExecFromDataSolanaCall)

    def make_tx_exec_from_account_ix(self) -> SolTxIx:
        ix_data_list = (
            NeonEvmIxCode.TxExecFromAccount.value.to_bytes(1, byteorder="little"),
            self._treasury_pool_index_buf,
        )
        return self._make_holder_ix(bytes().join(ix_data_list), self._acct_meta_list)

    def make_tx_exec_from_account_solana_call_ix(self) -> SolTxIx:
        ix_data_list = (
            NeonEvmIxCode.TxExecFromAccountSolanaCall.value.to_bytes(1, byteorder="little"),
            self._treasury_pool_index_buf,
        )
        return self._make_holder_ix(bytes().join(ix_data_list), self._acct_meta_list)

    def make_tx_step_from_account_ix(self, mode: NeonIxMode, step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(NeonEvmIxCode.TxStepFromAccount, mode, step_cnt, index, None)

    def make_tx_step_from_account_no_chain_id_ix(self, mode: NeonIxMode, step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(NeonEvmIxCode.TxStepFromAccountNoChainId, mode, step_cnt, index, None)

    def make_tx_step_from_data_ix(self, mode: NeonIxMode, step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(NeonEvmIxCode.TxStepFromData, mode, step_cnt, index, self._rlp_tx)

    def make_cancel_ix(self) -> SolTxIx:
        self.validate_protocol()

        ix_data_list = (
            NeonEvmIxCode.CancelWithHash.value.to_bytes(1, byteorder="little"),
            self._neon_tx_hash.to_bytes(),
        )

        acct_meta_list = [
            SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
        ]

        if self._base_tx_acct_set.is_empty:
            _LOG.debug("Cancel uses normal address list")
            acct_meta_list.extend(self._acct_meta_list)
        else:
            _LOG.debug("Cancel uses readonly address list")
            acct_meta_list.extend(self._ro_acct_meta_list)

        return SolTxIx(program_id=self.ID, data=bytes().join(ix_data_list), accounts=tuple(acct_meta_list))

    def make_start_skd_tx_from_data_ix(self, neon_tx_idx: int) -> SolTxIx:
        return self._make_skd_tx_start_ix(neon_tx_idx, NeonEvmIxCode.SkdTxStartFromData, self._rlp_tx)

    def make_start_skd_tx_from_account_ix(self, neon_tx_idx: int) -> SolTxIx:
        return self._make_skd_tx_start_ix(neon_tx_idx, NeonEvmIxCode.SkdTxStartFromAccount, bytes())

    def make_skip_skd_tx_from_data_ix(self, neon_tx_idx: int) -> SolTxIx:
        return self._make_skd_tx_ix(NeonEvmIxCode.SkdTxSkipFromData, neon_tx_idx, self._rlp_tx, list())

    def make_skip_skd_tx_from_account_ix(self, neon_tx_idx: int) -> SolTxIx:
        return self._make_skd_tx_ix(NeonEvmIxCode.SkdTxSkipFromAccount, neon_tx_idx, bytes(), list())

    def make_finish_skd_tx_ix(self, neon_tx_idx: int) -> SolTxIx:
        return self._make_skd_tx_ix(NeonEvmIxCode.SkdTxFinish, neon_tx_idx, bytes(), list())

    def make_destroy_skd_tree_ix(self) -> SolTxIx:
        assert not self._skd_tree_addr.is_empty
        self.validate_protocol()

        ix_code = NeonEvmIxCode.SkdTreeDestroy
        ix_data_list = (
            ix_code.value.to_bytes(1, byteorder="little"),
            self._treasury_pool_index_buf,
        )

        acct_meta_list = [
            SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            SolAccountMeta(pubkey=self._base_tx_acct_set.payer, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._treasury_pool_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._skd_tree_addr, is_signer=False, is_writable=True),
        ]

        return SolTxIx(program_id=self.ID, data=bytes().join(ix_data_list), accounts=tuple(acct_meta_list))

    # protected:

    def _make_tx_exec_from_data_ix(self, ix_code: NeonEvmIxCode) -> SolTxIx:
        self.validate_protocol()

        ix_data_list = (
            ix_code.value.to_bytes(1, byteorder="little"),
            self._treasury_pool_index_buf,
            self._rlp_tx,
        )
        return self._make_holder_ix(ix_data=bytes().join(ix_data_list), acct_meta_list=self._acct_meta_list)

    def _make_tx_step_ix(
        self,
        ix_code: NeonEvmIxCode,
        mode: NeonIxMode,
        step_cnt: int,
        index: int,
        data: bytes | None,
    ) -> SolTxIx:
        ix_data_list = (
            ix_code.value.to_bytes(1, byteorder="little"),
            self._treasury_pool_index_buf,
            step_cnt.to_bytes(4, byteorder="little"),
            index.to_bytes(4, byteorder="little"),
        )

        ix_data = bytes().join(ix_data_list)
        if data is not None:
            ix_data += data

        assert mode != NeonIxMode.Unknown
        if mode == NeonIxMode.Readable:
            return self._make_holder_ix(ix_data, self._ro_acct_meta_list)
        elif mode == NeonIxMode.Writable:
            return self._make_holder_ix(ix_data, self._acct_meta_list)
        elif mode == NeonIxMode.BaseTx:
            return self._make_holder_ix(ix_data, self._base_tx_acct_meta_list)

        return self._make_holder_ix(ix_data, self._rw_acct_meta_list)

    def _make_holder_ix(self, ix_data: bytes, acct_meta_list: list[SolAccountMeta]) -> SolTxIx:
        self.validate_protocol()

        acct_meta_list = [
            SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            SolAccountMeta(pubkey=self._treasury_pool_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=SolSysProg.ID, is_signer=False, is_writable=False),
        ] + acct_meta_list

        return SolTxIx(program_id=self.ID, data=ix_data, accounts=tuple(acct_meta_list))

    def _make_skd_tx_start_ix(self, skd_tx_idx: int, ix_code: NeonEvmIxCode, ix_data: bytes) -> SolTxIx:
        # fmt: off
        acct_meta_list = [
             SolAccountMeta(pubkey=SolSysProg.ID, is_signer=False, is_writable=False),
             SolAccountMeta(pubkey=self._base_tx_acct_set.payer, is_signer=False, is_writable=True),
        ] + self._base_tx_acct_meta_list
        # fmt: on

        return self._make_skd_tx_ix(ix_code, skd_tx_idx, ix_data, acct_meta_list)

    def _make_skd_tx_ix(
        self,
        ix_code: NeonEvmIxCode,
        skd_tx_idx: int,
        ix_data: bytes,
        acct_meta_list: list[SolAccountMeta],
    ) -> SolTxIx:
        assert not self._skd_tree_addr.is_empty

        self.validate_protocol()

        ix_data_list = (
            ix_code.value.to_bytes(1, byteorder="little"),
            skd_tx_idx.to_bytes(4, byteorder="little"),
            ix_data,
        )

        acct_meta_list = [
            SolAccountMeta(pubkey=self._holder_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._skd_tree_addr, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self._payer, is_signer=True, is_writable=True),
            SolAccountMeta(pubkey=self._token_sol_addr, is_signer=False, is_writable=True),
        ] + acct_meta_list

        return SolTxIx(program_id=self.ID, data=bytes().join(ix_data_list), accounts=tuple(acct_meta_list))

    @property
    def _ro_acct_meta_list(self) -> list[SolAccountMeta]:
        return self._get_ro_acct_meta_list()

    @reset_cached_method
    def _get_ro_acct_meta_list(self) -> list[SolAccountMeta]:
        if self._base_tx_acct_set.is_empty:
            return list(
                map(
                    lambda x: SolAccountMeta(x.pubkey, x.is_signer, is_writable=True),
                    self._acct_meta_list,
                )
            )

        return list(
            map(
                lambda x: SolAccountMeta(
                    x.pubkey,
                    x.is_signer,
                    is_writable=(self._base_tx_acct_set.sender == x.pubkey),
                ),
                self._acct_meta_list,
            )
        )

    @property
    def _base_tx_acct_meta_list(self) -> list[SolAccountMeta]:
        if self._base_tx_acct_set.is_empty:
            return self._ro_acct_meta_list
        return self._get_base_tx_acct_meta_list()

    @reset_cached_method
    def _get_base_tx_acct_meta_list(self) -> list[SolAccountMeta]:
        meta_list = [SolAccountMeta(self._base_tx_acct_set.sender, is_signer=False, is_writable=True)]
        _LOG.debug("add sender: %s", self._base_tx_acct_set.sender)
        if self._base_tx_acct_set.payer != self._base_tx_acct_set.sender:
            _LOG.debug("add payer: %s", self._base_tx_acct_set.payer)
            meta_list.append(SolAccountMeta(self._base_tx_acct_set.payer, is_signer=False, is_writable=True))
        if (not self._addr_set) or (self._base_tx_acct_set.receiver in self._addr_set):
            _LOG.debug("add receiver: %s", self._base_tx_acct_set.receiver)
            meta_list.append(SolAccountMeta(self._base_tx_acct_set.receiver, is_signer=False, is_writable=False))

        contract_addr = self._base_tx_acct_set.receiver_contract
        if (not self._addr_set) or (contract_addr in self._addr_set):
            _LOG.debug("add receiver contract: %s", contract_addr)
            meta_list.append(SolAccountMeta(contract_addr, is_signer=False, is_writable=False))
        return meta_list

    @property
    def _rw_acct_meta_list(self) -> list[SolAccountMeta]:
        return self._get_rw_acct_meta_list()

    @reset_cached_method
    def _get_rw_acct_meta_list(self) -> list[SolAccountMeta]:
        return list(
            map(
                lambda x: SolAccountMeta(
                    x.pubkey,
                    x.is_signer,
                    is_writable=(SolPubKey.from_raw(x.pubkey) not in self._ro_addr_set),
                ),
                self._acct_meta_list,
            )
        )

    @reset_cached_method
    def _get_rw_acct_key_list(self) -> Sequence[SolPubKey]:
        base_key_list = [
            self._holder_addr,
            self._payer,
            self._treasury_pool_addr,
            self._token_sol_addr,
        ]
        return tuple(base_key_list + [SolPubKey.from_raw(x.pubkey) for x in self._acct_meta_list if x.is_writable])

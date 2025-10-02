from __future__ import annotations

import logging
import uuid
from typing import Any, Annotated, Final, Sequence, ClassVar, Self

from pydantic import Field, PlainValidator, AliasChoices, PlainSerializer, ConfigDict
from strenum import StrEnum

from ..ethereum.bin_str import EthBinStrField, EthBinStr
from ..ethereum.hash import EthTxHashField, EthTxHash, EthAddressField, EthZeroAddressField, EthAddress, EthHash32Field
from ..ethereum.transaction import EthTx
from ..neon.address import NeonAddress, NeonAddressField
from ..neon.neon_program import NeonProgCfg, NeonProg, TokenInfo
from ..neon.transaction_model import NeonTxModel, NeonSkdTxStatusField, NeonSkdTxStatus, NeonTxType
from ..solana.account import SolAccountModel
from ..solana.instruction import SolAccountMeta
from ..solana.pubkey import SolPubKeyField, SolPubKey
from ..utils.cached import cached_property, cached_method
from ..utils.format import bytes_to_hex, if_none
from ..utils.pydantic import HexUIntField, DecIntField, BaseModel as _BaseModel, RootModel, DecUIntField

_LOG = logging.getLogger(__name__)


class _BaseRespModel(_BaseModel):
    _model_config = _BaseModel.model_config.copy()
    _model_config.pop("extra")

    model_config = ConfigDict(
        extra="allow",
        **_model_config,
    )


def _gen_unique_id() -> str:
    value = str(uuid.uuid4())
    _LOG.debug("generate ID %s for core-rpc", value)
    return value


class CoreApiRequest(_BaseModel):
    ctx_id: str = Field(serialization_alias="id", default_factory=_gen_unique_id)


class CoreApiResultCode(StrEnum):
    Success = "success"
    Error = "error"
    Unknown = "unknown"

    @classmethod
    def from_raw(cls, value: str | CoreApiResultCode) -> Self:
        if isinstance(value, cls):
            return value

        try:
            value = value.lower()
            return cls(value)
        except (BaseException,):
            _LOG.error("unknown result %s from core api", value.upper())
            return cls.Unknown


CoreApiResultField = Annotated[CoreApiResultCode, PlainValidator(CoreApiResultCode.from_raw)]


class CoreApiResp(_BaseRespModel):
    result: CoreApiResultField
    error: str = None
    error_code: DecIntField | None = None

    value: dict | list[dict] | str | list[int] | None = None
    logs: list[dict] = Field(default_factory=list)


class _AccountModel(_BaseModel):
    address: EthZeroAddressField
    chain_id: DecUIntField

    @classmethod
    def from_raw(cls, raw: _AccountModel | NeonAddress) -> Self:
        if isinstance(raw, _AccountModel):
            return raw
        return cls(address=raw.eth_address, chain_id=raw.chain_id)


class NeonAccountListRequest(CoreApiRequest):
    account_list: list[_AccountModel] = Field(serialization_alias="account")
    slot: DecUIntField | None

    @classmethod
    def from_raw(cls, account_list: Sequence[NeonAddress], slot: int | None) -> Self:
        return cls(account_list=[_AccountModel.from_raw(a) for a in account_list], slot=slot)


class NeonAccountStatus(StrEnum):
    Ok = "Ok"
    Legacy = "Legacy"
    Empty = "Empty"

    @classmethod
    def from_raw(cls, value: str | NeonAccountStatus) -> Self:
        if isinstance(value, cls):
            return value

        try:
            return cls(value)
        except (BaseException,):
            _LOG.error("unknown neon account status %s from core-api", value.upper())
            return cls.Empty


# Type for Pydantic, it just annotates rules for deserialization
NeonAccountStatusField = Annotated[NeonAccountStatus, PlainValidator(NeonAccountStatus.from_raw)]


class NeonAccountModel(_BaseRespModel):
    neon_address: NeonAddressField
    user_sol_address: SolPubKeyField = Field(SolPubKey.default(), validation_alias="user_pubkey")
    status: NeonAccountStatusField
    state_tx_cnt: DecUIntField = Field(validation_alias=AliasChoices("trx_count", "state_tx_cnt"))
    balance: HexUIntField
    sol_address: SolPubKeyField = Field(validation_alias=AliasChoices("solana_address", "sol_address"))
    contract_sol_address: SolPubKeyField = Field(
        validation_alias=AliasChoices("contract_solana_address", "contract_sol_address")
    )
    container_sol_address: SolPubKeyField = Field(
        default=SolPubKey.default(),
        validation_alias=AliasChoices("container_address", "container_sol_address")
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, address: NeonAddress | None = None) -> Self:
        if not address:
            return super().from_dict(data)
        return cls._from_acct(address, data)

    @classmethod
    def new_empty(cls, address: NeonAddress) -> Self:
        return cls(
            neon_address=address,
            user_sol_address=SolPubKey.default(),
            status=NeonAccountStatus.Empty,
            sol_address=SolPubKey.default(),
            contract_sol_address=SolPubKey.default(),
            container_sol_address=SolPubKey.default(),
            state_tx_cnt=0,
            balance=0,
        )

    @classmethod
    def _from_acct(cls, address: NeonAddress, data: dict[str, Any]):
        data["neon_address"] = address
        return cls.model_validate(data)

    @property
    def chain_id(self) -> int:
        return self.neon_address.chain_id

    @property
    def eth_address(self) -> EthAddress:
        return self.neon_address.eth_address


class NeonContractRequest(CoreApiRequest):
    contract: EthZeroAddressField
    slot: DecUIntField | None


class NeonContractModel(_BaseRespModel):
    neon_address: NeonAddressField
    code: EthBinStrField
    sol_address: SolPubKeyField = Field(validation_alias="solana_address")

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, address: NeonAddress | None = None) -> Self:
        if not address:
            return super().from_dict(data)
        return cls._from_acct(address, data)

    @classmethod
    def _from_acct(cls, address: NeonAddress, data: dict[str, Any]) -> Self:
        chain_id: int = data.pop("chain_id", None) or address.chain_id

        # replace with the actual chain-id
        data["neon_address"] = NeonAddressField.from_raw(address, chain_id)
        return cls.model_validate(data)

    @property
    def chain_id(self) -> int:
        return self.neon_address.chain_id

    @property
    def has_code(self) -> bool:
        return not self.code.is_empty


class NeonStorageAtRequest(CoreApiRequest):
    contract: EthZeroAddressField
    index: HexUIntField
    slot: DecUIntField | None


class OpEarnAccountModel(_BaseModel):
    status: NeonAccountStatusField
    operator_key: SolPubKeyField
    neon_address: NeonAddressField
    token_sol_address: SolPubKeyField
    balance: DecUIntField

    @property
    def chain_id(self) -> int:
        return self.neon_address.chain_id

    @property
    def eth_address(self) -> EthAddress:
        return self.neon_address.eth_address


class BpfLoader2ProgModel(_BaseModel):
    version: int
    exec_address: SolPubKeyField = SolPubKeyField.default()

    @classmethod
    def from_data(cls, data: bytes) -> Self:
        if len(data) != 36:
            return cls(version=0)

        version = int.from_bytes(data[:4], "little")
        if version != 2:
            return cls(version=version)

        return cls(version=version, exec_address=SolPubKeyField.from_bytes(data[4:]))


class BpfLoader2ExecModel(_BaseModel):
    version: int
    deployed_slot: int = 0
    minimum_size: Final[int] = 8

    @classmethod
    def from_data(cls, data: bytes) -> Self:
        if len(data) < cls.minimum_size:
            return cls(version=0)

        version = int.from_bytes(data[:4], "little")
        if version != 3:
            return cls(version=version)

        return cls(version=version, deployed_slot=int.from_bytes(data[4:8], "little"))


class TokenModel(_BaseRespModel):
    chain_id: DecIntField = Field(serialization_alias="id", validation_alias=AliasChoices("id", "chain_id"))
    mint: SolPubKeyField = Field(serialization_alias="token", validation_alias=AliasChoices("token", "mint"))
    name: str

    @classmethod
    def from_raw(cls, raw: TokenInfo) -> Self:
        return cls(
            chain_id=raw.chain_id,
            mint=raw.mint,
            name=raw.name.lower(),
        )

    def to_token_info(self) -> TokenInfo:
        return TokenInfo(
            chain_id=self.chain_id,
            mint=self.mint,
            name=self.name.upper(),
        )


class EvmConfigModel(_BaseRespModel):
    deployed_slot: DecIntField

    evm_param_dict: dict[str, str] = Field(validation_alias=AliasChoices("config", "evm_param_dict"))
    token_list: list[TokenModel] = Field(validation_alias=AliasChoices("chains", "token_list"))

    status: str = Field(default="Ok")
    environment: str = Field(default="Unknown")

    version: str
    revision: str

    _default: ClassVar[EvmConfigModel | None] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, deployed_slot: int | None = None) -> Self:
        if deployed_slot is None:
            return super().from_dict(data)
        return cls._from_core_dict(deployed_slot, data)

    @classmethod
    def _from_core_dict(cls, deployed_slot: int, data: dict[str, Any]) -> Self:
        data["deployed_slot"] = deployed_slot

        return cls.model_validate(data)

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            opt_dict = dict()

            data = dict(
                deployed_slot=-1,
                evm_param_dict=dict(),
                token_list=list(),
                version="0.0.0-unk",
                revision="Unknown",
            )
            data.update(opt_dict)

            cls._default = cls.model_validate(data)
        return cls._default

    @property
    def is_empty(self) -> bool:
        return self.deployed_slot == -1

    @cached_property
    def package_version(self) -> str:
        return "Neon-EVM/v" + self.version + "-" + self.revision

    @cached_property
    def neon_prog_cfg(self) -> NeonProgCfg:
        return NeonProgCfg(
            deployed_slot=self.deployed_slot,
            treasury_pool_cnt=int(self.evm_param_dict.get("NEON_TREASURY_POOL_COUNT", 0)),
            treasury_pool_seed=bytes(self.evm_param_dict.get("NEON_TREASURY_POOL_SEED", ""), "utf-8"),
            treasury_payment=int(self.evm_param_dict.get("NEON_PAYMENT_TO_TREASURE", 0)),
            account_seed_version=int(self.evm_param_dict.get("NEON_ACCOUNT_SEED_VERSION", 0)),
            evm_version=self.version,
            evm_step_cnt=int(self.evm_param_dict.get("NEON_EVM_STEPS_MIN", 0)),
            holder_msg_size=int(self.evm_param_dict.get("NEON_HOLDER_MSG_SIZE", 0)),
            gas_limit_multiplier_wo_chain_id=int(self.evm_param_dict.get("NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID", 0)),
            tree_account_slot_out=int(self.evm_param_dict.get("NEON_TREE_ACCOUNT_TIMEOUT", 0)),
            tree_account_finish_tx_gas=int(self.evm_param_dict.get("NEON_TREE_ACCOUNT_FINISH_TRANSACTION_GAS", 0)),
            token_list=[token.to_token_info() for token in self.token_list],
        )


class HolderAccountRequest(CoreApiRequest):
    pubkey: SolPubKeyField

    @classmethod
    def from_raw(cls, pubkey: SolPubKey) -> Self:
        return cls(pubkey=pubkey)


class HolderAccountStatus(StrEnum):
    Empty = "Empty"
    Error = "Error"
    Holder = "Holder"
    Active = "Active"
    Finalized = "Finalized"
    ScheduledFinalized = "ScheduledFinalized"
    ScheduledCanceled = "ScheduledCanceled"

    @classmethod
    def from_raw(cls, value: str | HolderAccountStatus) -> Self:
        if isinstance(value, cls):
            return value

        try:
            return cls(value)
        except (BaseException,):
            _LOG.error("unknown holder status %s from core-api", value)
            return cls.Error


# Type for Pydantic, it just annotates rules for deserialization
HolderAccountStatusField = Annotated[HolderAccountStatus, PlainValidator(HolderAccountStatus.from_raw)]


class CoreApiHexStr(EthBinStr):
    _default: ClassVar[CoreApiHexStr | None] = None

    @classmethod
    def default(cls) -> Self:
        if not isinstance(cls._default, CoreApiHexStr):
            cls._default = cls(cls._empty_data)
        return cls._default

    @cached_method
    def _to_string(self) -> str:
        return bytes_to_hex(self._data, prefix="")

    def to_string(self, default: str | None = "") -> str | None:
        return super().to_string(default=default)


CoreApiHexStrField = Annotated[
    CoreApiHexStr,
    PlainValidator(CoreApiHexStr.from_raw),
    PlainSerializer(lambda v: v.to_string()),
]


class CoreApiTxModel(_BaseRespModel):
    from_address: EthZeroAddressField | SolPubKeyField = Field(
        validation_alias=AliasChoices("from", "from_address"),
        serialization_alias="from",
    )
    payer: EthZeroAddressField | SolPubKeyField
    solanaPayer: SolPubKeyField | None = Field(default=None)
    nonce: DecUIntField | None
    index: DecUIntField = 0
    to_address: EthAddressField = Field(
        default=EthAddress.default(),
        validation_alias=AliasChoices("to", "to_address"),
        serialization_alias="to",
    )
    value: HexUIntField
    call_data: CoreApiHexStrField = Field(
        validation_alias=AliasChoices("data", "call_data"),
        serialization_alias="data",
    )
    gas_limit: HexUIntField | None
    gas_price: HexUIntField | None
    max_fee_per_gas: HexUIntField = Field(default=0)
    max_priority_fee_per_gas: HexUIntField = Field(default=0)

    chain_id: DecUIntField | None = None

    @classmethod
    def from_neon_tx(cls, tx: NeonTxModel) -> Self:
        return cls(
            from_address=tx.from_address,
            payer=tx.payer,
            nonce=tx.nonce,
            index=tx.index,
            to_address=tx.to_address,
            value=tx.value,
            call_data=tx.call_data.to_bytes(),
            gas_limit=tx.gas_limit,
            gas_price=tx.gas_price or 0,
            max_fee_per_gas=tx.max_fee_per_gas or 0,
            max_priority_fee_per_gas=tx.max_priority_fee_per_gas or 0,
            chain_id=tx.chain_id,
        )

    @property
    def has_chain_id(self) -> bool:
        return if_none(self.chain_id, 0) != 0

    @cached_property
    def cost(self) -> int:
        return EthTx.calc_cost(self)

    @cached_property
    def effective_gas_price(self) -> int:
        return EthTx.calc_effective_gas_price(self)

    @cached_property
    def effective_gas_limit(self) -> int:
        return EthTx.calc_effective_gas_limit(self, NeonProg)

    @cached_property
    def is_fee_less(self) -> bool:
        return self.effective_gas_price == 0


class CoreApiBlockModel(_BaseModel):
    timestamp: DecUIntField | None = Field(default=None, serialization_alias="time")
    slot: DecUIntField | None = Field(default=None, serialization_alias="number")

    _default: ClassVar[CoreApiBlockModel | None] = None

    @classmethod
    def default(cls) -> Self:
        if not cls._default:
            cls._default = CoreApiBlockModel()
        return cls._default

    @classmethod
    def from_raw(cls, raw_list: list[str] | None) -> Self:
        if not raw_list:
            return cls.default()

        return cls(
            timestamp=int(raw_list[0], 16),  # noqa
            slot=int(raw_list[1], 16),       # noqa
        )

    @property
    def is_empty(self) -> bool:
        return self.slot is None


class HolderAccountModel(_BaseRespModel):
    address: SolPubKeyField

    status: HolderAccountStatusField
    size: DecUIntField = Field(default=0, validation_alias="len")
    owner: SolPubKeyField = Field(default=SolPubKey.default())

    neon_tx_hash: EthTxHashField = Field(default=EthTxHash.default(), validation_alias="tx")
    tx_type: DecUIntField = Field(default=0)
    tx: CoreApiTxModel | None = Field(default=None, validation_alias="tx_data")
    block: CoreApiBlockModel

    chain_id: DecUIntField = Field(default=0)
    evm_step_cnt: DecUIntField = Field(default=0, validation_alias="steps_executed")
    account_key_list: list[SolPubKeyField] = Field(default_factory=list, validation_alias="accounts")

    @classmethod
    def new_empty(cls, address: SolPubKey) -> Self:
        return cls(
            address=address,
            status=HolderAccountStatus.Empty,
            owner=SolPubKey.default(),
            block=CoreApiBlockModel.default(),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, address: NeonAddress, def_chain_id: int) -> Self:
        data["address"] = address
        data["block"] = CoreApiBlockModel.from_raw(data.pop("block_params", None))
        data["chain_id"] = data.get("chain_id", def_chain_id)
        return cls.model_validate(data)

    @cached_property
    def sender(self) -> NeonAddress:
        if self.tx is None:
            return NeonAddress.default()

        return NeonAddress.from_raw(self.tx.from_address, self.chain_id)

    @cached_property
    def payer(self) -> NeonAddress:
        if self.tx is None:
            return NeonAddress.default()

        return NeonAddress.from_raw(self.tx.payer, self.chain_id)

    @cached_property
    def nonce(self) -> int:
        return self.tx.nonce or 0 if self.tx else 0

    @cached_property
    def receiver(self) -> NeonAddress:
        if self.tx is None:
            return NeonAddress.default()

        elif not self.tx.to_address.is_empty:
            return NeonAddress.from_raw(self.tx.to_address, self.chain_id)

        contract_addr = EthTx.calc_contract_address(self.tx)
        return NeonAddress.from_raw(contract_addr, self.chain_id)

    @cached_property
    def is_scheduled_tx(self) -> bool:
        return NeonTxType.is_scheduled_tx(self.tx_type)

    @property
    def is_empty(self) -> bool:
        s = HolderAccountStatus
        return self.status in (s.Empty, s.Error)

    @property
    def is_active(self) -> bool:
        s = HolderAccountStatus
        return self.status in (s.Active, s.ScheduledFinalized, s.ScheduledCanceled)


class _CrateModel(_BaseRespModel):
    version: str


class _VersionModel(_BaseRespModel):
    commit_id: str


class CoreApiBuildModel(_BaseRespModel):
    crate_info: _CrateModel
    version_control: _VersionModel


class EmulSolAccountModel(_BaseModel):
    balance: DecUIntField = Field(serialization_alias="lamports")
    data: CoreApiHexStrField
    owner: SolPubKeyField
    executable: bool
    rent_epoch: DecUIntField

    @classmethod
    def from_raw(cls, raw: SolAccountModel | None) -> Self | None:
        if raw is None:
            return None

        return cls(
            balance=raw.balance,
            data=raw.data,
            owner=raw.owner,
            executable=raw.executable,
            rent_epoch=raw.rent_epoch,
        )


class EmulNeonAccountModel(_BaseModel):
    nonce: DecUIntField | None = None
    balance: HexUIntField | None = None


class EmulTraceCfgModel(_BaseModel):
    neon_account_dict: dict[EthZeroAddressField, EmulNeonAccountModel] = Field(serialization_alias="stateOverrides")
    block: CoreApiBlockModel | None = Field(default=None, serialization_alias="blockOverrides")


class EmulNeonCallRequest(CoreApiRequest):
    tx: CoreApiTxModel
    evm_step_limit: DecUIntField = Field(serialization_alias="step_limit")
    # evm_account_limit: DecUIntField = Field(serialization_alias="account_limit")
    token_list: list[TokenModel] = Field(serialization_alias="chains")
    trace_cfg: EmulTraceCfgModel | None = Field(serialization_alias="trace_config")
    preload_sol_address_list: list[SolPubKeyField] = Field(serialization_alias="accounts")
    sol_account_dict: dict[SolPubKeyField, EmulSolAccountModel | None] | None = Field(
        serialization_alias="solana_overrides"
    )
    slot: DecUIntField | None


# >> NEW VERSION
# class EmulFromHolderRequest(CoreApiRequest):
#     holder_address: SolPubKeyField = Field(serialization_alias="holder_pubkey")
#     evm_step_limit: DecUIntField = Field(serialization_alias="step_limit")
#     evm_account_limit: DecUIntField = Field(serialization_alias="account_limit")
#     token_list: list[TokenModel] = Field(serialization_alias="chains")
#     slot: DecUIntField | None
# << NEW VERSION


class EmulNeonCallExitCode(StrEnum):
    Revert = "revert"
    Succeed = "succeed"
    StepLimitExceeded = "step limit exceeded"
    Unknown = "unknown"

    @classmethod
    def from_raw(cls, value: str | EmulNeonCallExitCode) -> Self:
        if isinstance(value, cls):
            return value

        try:
            value = value.lower()
            return cls(value)
        except (BaseException,):
            _LOG.error(f"unknown emulator exit {value}")
            return cls.Unknown


EmulNeonCallExitCodeField = Annotated[EmulNeonCallExitCode, PlainValidator(EmulNeonCallExitCode.from_raw)]


class EmulAccountMetaModel(_BaseRespModel):
    pubkey: SolPubKeyField
    is_writable: bool
    is_signer: bool = False

    @classmethod
    def from_raw(cls, raw: SolAccountMeta) -> Self:
        return cls(pubkey=raw.pubkey, is_writable=raw.is_writable, is_signer=raw.is_signer)

    def to_sol_account_meta(self) -> SolAccountMeta:
        return SolAccountMeta(pubkey=self.pubkey, is_writable=self.is_writable, is_signer=self.is_signer)


class EmulNeonCallResp(_BaseRespModel):
    exit_code: EmulNeonCallExitCodeField = Field(validation_alias="exit_status")
    external_sol_call: bool = Field(validation_alias="external_solana_call")
    revert_before_sol_call: bool = Field(validation_alias="reverts_before_solana_calls")
    revert_after_sol_call: bool = Field(validation_alias="reverts_after_solana_calls")
    is_block_used: bool = Field(False, validation_alias="is_timestamp_number_used")

    result: EthBinStrField
    evm_step_cnt: DecUIntField = Field(validation_alias="steps_executed")
    used_gas: DecUIntField
    iter_cnt: DecUIntField = Field(alias="iterations")

    raw_meta_list: list[EmulAccountMetaModel] = Field(validation_alias="solana_accounts", default_factory=list)

    @cached_property
    def sol_account_meta_list(self) -> Sequence[SolAccountMeta]:
        return tuple([a.to_sol_account_meta() for a in self.raw_meta_list])

    @cached_property
    def sol_address_list(self) -> list[SolPubKey]:
        return [a.pubkey for a in self.raw_meta_list]


class EmulMultipleNeonCallRequest(CoreApiRequest):
    sol_tx_request: EmulSolTxIxRequest = Field(serialization_alias="solana_tx")
    neon_tx_list: list[CoreApiTxModel] = Field(serialization_alias="tx")
    evm_step_limit: DecUIntField = Field(serialization_alias="step_limit")
    # evm_account_limit: DecUIntField = Field(serialization_alias="account_limit")
    token_list: list[TokenModel] = Field(serialization_alias="chains")
    preload_sol_address_list: list[SolPubKeyField] = Field(serialization_alias="accounts")
    slot: DecUIntField | None


class EmulMultipleNeonCallResp(RootModel):
    root: list[EmulNeonCallResp] = Field(default_factory=list)


# TODO: NEW VERSION
# class EmulSolTxIxRequest(_BaseModel):
#     prog_id: SolPubKeyField = Field(serialization_alias="program_id")
#     account_list: list[EmulAccountMetaModel] = Field(serialization_alias="accounts")
#     data: CoreApiHexStrField
#
#     @classmethod
#     def from_raw(cls, ix: SolTxIx) -> Self:
#         return cls(
#             prog_id=ix.program_id,
#             account_list=list(map(lambda acct: EmulAccountMetaModel.from_raw(acct), ix.accounts)),
#             data=ix.data,
#         )
#
#
# class EmulSolTxRequest(CoreApiRequest):
#     cu_limit: DecUIntField = Field(serialization_alias="compute_units")
#     heap_size: DecUIntField = Field(serialization_alias="heap_size")
#     ix_list: list[EmulSolTxIxRequest] = Field(serialization_alias="instructions")
# << NEW VERSION


class EmulSolTxIxRequest(CoreApiRequest):
    cu_limit: DecUIntField = Field(serialization_alias="compute_units")
    heap_size: DecUIntField = Field(serialization_alias="heap_size")
    account_cnt_limit: DecUIntField = Field(serialization_alias="account_limit")
    verify: bool
    blockhash: CoreApiHexStrField
    tx_list: list[CoreApiHexStrField] = Field(serialization_alias="transactions")


class EmulSolTxIxMetaModel(_BaseRespModel):
    error: dict | str | None
    log_list: list[str] = Field(default_factory=list, validation_alias="logs")
    cu_consumed: DecUIntField = Field(validation_alias="executed_units")


class EmulSolTxIxListResp(_BaseRespModel):
    meta_list: list[EmulSolTxIxMetaModel] = Field(validation_alias="transactions")


# >> NEW VERSION
# class EmulSolTxIxListResp(_BaseRespModel):
#     meta_list: list[EmulSolTxIxMetaModel] = Field(validation_alias="instructions")
# << NEW VERSION


class NeonSkdTreeRequest(CoreApiRequest):
    payer: _AccountModel = Field(serialization_alias="origin")
    nonce: DecUIntField
    slot: DecUIntField | None

    @classmethod
    def from_raw(cls, payer: NeonAddress, nonce: int, slot: int | None = None) -> Self:
        return cls(
            payer=_AccountModel.from_raw(payer),
            nonce=nonce,
            slot=slot,
        )


class NeonSkdTreeNodeModel(_BaseRespModel):
    status: NeonSkdTxStatusField
    result_hash: EthHash32Field
    neon_tx_hash: EthTxHashField = Field(validation_alias="transaction_hash")
    gas_limit: HexUIntField
    value: HexUIntField
    child_tx_idx: DecUIntField = Field(validation_alias="child_transaction")
    success_exec_limit: DecUIntField = Field(validation_alias="success_execute_limit")
    parent_cnt: DecUIntField = Field(validation_alias="parent_count")


class NeonSkdTreeStatus(StrEnum):
    Empty = "Empty"
    Error = "Error"
    Ok = "Ok"

    @classmethod
    def from_raw(cls, value: str | NeonSkdTreeStatus) -> Self:
        if isinstance(value, cls):
            return value

        try:
            return cls(value)
        except (BaseException,):
            _LOG.error("unknown Neon scheduled Tree status %s from core-api", value)
            return cls.Error


NeonSkdTreeStatusField = Annotated[NeonSkdTreeStatus, PlainValidator(NeonSkdTreeStatus.from_raw)]


class NeonSkdTreeModel(_BaseRespModel):
    status: NeonSkdTreeStatusField
    address: SolPubKeyField = Field(validation_alias=AliasChoices("address", "pubkey"))

    payer: EthAddressField = Field(validation_alias=AliasChoices("payer", "origin"))
    last_slot: DecUIntField
    chain_id: DecUIntField
    max_fee_per_gas: HexUIntField
    max_priority_fee_per_gas: HexUIntField
    balance: HexUIntField
    last_idx: DecUIntField = Field(validation_alias=AliasChoices("last_idx", "last_index"))

    node_list: list[NeonSkdTreeNodeModel] = Field(
        default_factory=list,
        validation_alias=AliasChoices("node_list", "transactions"),
    )

    @classmethod
    def new_empty(cls) -> Self:
        return cls(
            status=NeonSkdTreeStatus.Empty,
            address=SolPubKey.default(),
            payer=EthAddress.default(),
            last_slot=0,
            chain_id=0,
            max_fee_per_gas=0,
            max_priority_fee_per_gas=0,
            balance=0,
            last_idx=0,
            node_list=list(),
        )

    @cached_property
    def is_exist(self) -> bool:
        return len(self.node_list) > 0

    @cached_property
    def root_neon_tx_hash(self) -> EthTxHash:
        return self.node_list[0].neon_tx_hash if self.is_exist else EthTxHash.default()

    @cached_property
    def active_status(self) -> NeonSkdTxStatus:
        if not self.is_exist:
            return NeonSkdTxStatus.Destroyed

        last_status = NeonSkdTxStatus.Success
        for node in self.node_list:
            if (status := node.status) in (status.InProgress, status.NotStarted):
                return status
            last_status = status
        return last_status

    def is_destroyable(self, current_slot: int, slot_out: int) -> bool:
        return current_slot - self.last_slot > slot_out

    def get_neon_skd_status(self, index: int) -> NeonSkdTxStatus:
        if len(self.node_list) <= index:
            return NeonSkdTxStatus.Destroyed

        node = self.node_list[index]
        if (node.status != node.status.NotStarted) or node.parent_cnt:
            return node.status

        if not node.success_exec_limit:
            return node.status.ToStart

        # fmt: off
        success_exec_cnt = sum(
            (n.child_tx_idx == index) and (n.status == n.status.Success)
            for n in self.node_list[:index]
        )

        return (
            NeonSkdTxStatus.ToStart
            if success_exec_cnt >= node.success_exec_limit
            else NeonSkdTxStatus.ToSkip
        )
        # fmt: on

    def find_neon_skd_node(self, neon_tx_hash: EthTxHash) -> None | tuple[int, NeonSkdTreeNodeModel]:
        for idx, node in enumerate(self.node_list):
            if node.neon_tx_hash == neon_tx_hash:
                return idx, node
        return None

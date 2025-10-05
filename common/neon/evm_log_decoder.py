from __future__ import annotations

import abc
import base64
import enum
import logging
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Final, Sequence, Annotated, ClassVar, Self, Literal

from eth_bloom import BloomFilter
from pydantic import PlainValidator, PlainSerializer

from ..ethereum.bin_str import EthBinStrField
from ..ethereum.hash import (
    EthTxHash,
    EthTxHashField,
    EthBlockHash,
    EthBlockHashField,
    EthAddressField,
    EthHash32Field,
    EthAddress,
)
from ..solana.signature import SolTxSigField
from ..solana.transaction_decoder import SolTxIxMetaInfo
from ..utils.cached import cached_property, cached_method
from ..utils.format import str_fmt_object, str_content_object
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class NeonTxEventModelType(enum.IntEnum):
    Unknown = 0

    Log = 1

    StepReset = 50
    InvalidRevision = 51

    EnterCall = 101
    EnterCallCode = 102
    EnterStaticCall = 103
    EnterDelegateCall = 104
    EnterCreate = 105
    EnterCreate2 = 106

    ExitStop = 201
    ExitReturn = 202
    ExitSelfDestruct = 203
    ExitRevert = 204
    ExitSendAll = 205

    Return = 300
    Cancel = 301
    Lost = 302


NeonTxEventModelTypeField = Annotated[
    NeonTxEventModelType,
    PlainValidator(lambda v: NeonTxEventModelType(v)),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class NeonTxEventModel(BaseModel):
    Type: Final[NeonTxEventModelType] = NeonTxEventModelType

    event_type: NeonTxEventModelTypeField
    is_hidden: bool

    neon_tx_hash: EthTxHashField

    address: EthAddressField
    topic_list: list[EthHash32Field]
    data: EthBinStrField

    sol_tx_sig: SolTxSigField
    sol_ix_idx: int
    sol_inner_ix_idx: int | None

    total_gas_used: int
    total_step_cnt: int
    is_reverted: bool
    event_level: int
    event_order: int

    block_hash: EthBlockHashField
    slot: int
    neon_tx_idx: int
    block_log_idx: int | None
    neon_tx_log_idx: int | None

    @cached_property
    def str_ident(self) -> str:
        ident = (self.sol_tx_sig.to_string(), self.slot, self.sol_ix_idx, self.sol_inner_ix_idx)
        return ":".join(str(s) for s in ident if s)

    @cached_property
    def log_bloom(self) -> int:
        if self.event_type != self.Type.Log or self.is_hidden:
            return 0
        iter_list = [self.address.to_bytes()]
        iter_list.extend(map(lambda x: x.to_bytes(), self.topic_list))
        bloom = BloomFilter.from_iterable(iter_list)
        return int(bloom)


@dataclass(frozen=True)
class NeonTxErrorLogInfo:
    class ErrorCode(IntEnum):
        Custom = 0
        ProgramError = enum.auto()
        PubkeyError = enum.auto()
        RlpError = enum.auto()
        Secp256k1Error = enum.auto()
        BincodeError = enum.auto()
        BorshError = enum.auto()
        FromHexError = enum.auto()
        TryFromIntError = enum.auto()
        TryFromSliceError = enum.auto()
        Utf8Error = enum.auto()
        AccountMissing = enum.auto()
        AccountBlocked = enum.auto()
        AccountCreatedByAnotherTransaction = enum.auto()
        AccountInvalidTag = enum.auto()
        AccountInvalidOwner = enum.auto()
        AccountInvalidKey = enum.auto()
        AccountInvalidData = enum.auto()
        AccountNotWritable = enum.auto()
        AccountNotSigner = enum.auto()
        AccountNotRentExempt = enum.auto()
        AccountAlreadyInitialized = enum.auto()
        AccountLegacy = enum.auto()
        UnauthorizedOperator = enum.auto()
        StorageAccountUninitialized = enum.auto()
        StorageAccountFinalized = enum.auto()
        StorageAccountInvalidTag = enum.auto()
        UnknownPrecompileMethodSelector = enum.auto()
        InsufficientBalance = enum.auto()
        InvalidTransferToken = enum.auto()
        OutOfGas = enum.auto()
        OutOfPriorityFee = enum.auto()
        GasReceiverInvalidChainId = enum.auto()
        StackOverflow = enum.auto()
        StackUnderflow = enum.auto()
        PushOutOfBounds = enum.auto()
        MemoryAccessOutOfLimits = enum.auto()
        ReturnDataCopyOverflow = enum.auto()
        StaticModeViolation = enum.auto()
        InvalidJump = enum.auto()
        InvalidOpcode = enum.auto()
        UnknownOpcode = enum.auto()
        NonceOverflow = enum.auto()
        InvalidTransactionNonce = enum.auto()
        InvalidChainId = enum.auto()
        DeployToExistingAccount = enum.auto()
        EVMObjectFormatNotSupported = enum.auto()
        ContractCodeSizeLimit = enum.auto()
        SenderHasDeployedCode = enum.auto()
        IntegerOverflow = enum.auto()
        OutOfBounds = enum.auto()
        HolderInvalidOwner = enum.auto()
        HolderInsufficientSize = enum.auto()
        HolderInvalidHash = enum.auto()
        AccountSpaceAllocationFailure = enum.auto()
        InvalidAccountForCall = enum.auto()
        UnavalableExternalSolanaCall = enum.auto()
        RecursiveCall = enum.auto()
        ExternalCallFailed = enum.auto()
        OperatorBalanceInvalidOwner = enum.auto()
        OperatorBalanceMissing = enum.auto()
        OperatorBalanceInvalidChainId = enum.auto()
        OperatorBalanceInvalidAddress = enum.auto()
        PriorityFeeNotSpecified = enum.auto()
        PriorityFeeParsingError = enum.auto()
        PriorityFeeError = enum.auto()
        TreeAccountNotReadyForDestruction = enum.auto()
        TreeAccountLastIdxOverflow = enum.auto()
        TreeAccountInvalidPayer = enum.auto()
        TreeAccountInvalidChainId = enum.auto()
        TreeAccountTxInvalidType = enum.auto()
        TreeAccountTxInvalidData = enum.auto()
        TreeAccountTxInvalidChildIdx = enum.auto()
        TreeAccountTxInvalidParentCount = enum.auto()
        TreeAccountTxInvalidSuccessLimit = enum.auto()
        TreeAccountTxNotFound = enum.auto()
        TreeAccountTxInvalidStatus = enum.auto()
        TreeAccountInvalidMaxFeePerGas = enum.auto()
        TreeAccountInvalidGasLimit = enum.auto()
        TreeAccountAlreadyExists = enum.auto()
        NotScheduledTransaction = enum.auto()
        ScheduledTxInvalidTreeAccount = enum.auto()
        ScheduledTxNoExitStatus = enum.auto()
        ScheduledTxAlreadyInProgress = enum.auto()
        ScheduledTxAlreadyComplete = enum.auto()
        ScheduledTxInvalidIdx = enum.auto()
        NotClassicTransaction = enum.auto()
        TreasuryMissing = enum.auto()
        AccountInvalidHeader = enum.auto()
        RevertAfterSolanaCall = enum.auto()
        UnsupportedEthereumTransactionType = enum.auto()
        UnsupportedNeonTransactionType = enum.auto()
        InterruptedCall = enum.auto()
        UnknownError = enum.auto()

    code: ErrorCode
    data: bytes
    message: str

    @classmethod
    def from_raw(cls, code: int, data: bytes, message: str):
        if code < cls.ErrorCode.Custom or code >= cls.ErrorCode.UnknownError:
            error_code = cls.ErrorCode.UnknownError
        else:
            error_code = cls.ErrorCode(code)

        return cls(
            code=error_code,
            data=data[4:],
            message=message,
        )


@dataclass(frozen=True)
class NeonTxLogInfo:
    neon_tx_hash: EthTxHash
    root_neon_tx_hash: EthTxHash
    tx_ix_miner: EthAddress
    tx_ix_step: NeonTxIxStepInfo
    tx_ix_gas: NeonTxIxLogGasInfo
    tx_ix_priority_fee: NeonTxIxPriorityFeeInfo
    tx_ix_base_fee: NeonTxIxBaseFeeInfo
    tx_block: NeonTxBlockInfo
    tx_return: NeonTxLogReturnInfo
    tx_event_list: list[NeonTxEventModel]
    tx_error_list: list[NeonTxErrorLogInfo]
    is_truncated: bool
    is_already_finalized: bool


@dataclass(frozen=True)
class NeonTxLogReturnInfo:
    event_type: NeonTxEventModel.Type
    total_gas_used: int
    status: int = 0
    #
    Success: Final[int] = 1
    Failed: Final[int] = 0
    #
    _Default: ClassVar[NeonTxLogReturnInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(event_type=NeonTxEventModel.Type.Unknown, total_gas_used=0, status=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.total_gas_used == 0

    @cached_method
    def to_string(self) -> str:
        if self.is_empty:
            return str_content_object(self, "Empty")
        return str_fmt_object(self, skip_key_list=["Success", "Failed"])

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


@dataclass(frozen=True)
class NeonTxIxLogGasInfo:
    gas_used: int
    total_gas_used: int

    _Default: ClassVar[NeonTxIxLogGasInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(gas_used=0, total_gas_used=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.gas_used == 0


@dataclass(frozen=True)
class NeonTxIxPriorityFeeInfo:
    # Denominated in gas tokens.
    priority_fee_paid: int

    _Default: ClassVar[NeonTxIxPriorityFeeInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(priority_fee_paid=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.priority_fee_paid == 0


@dataclass(frozen=True)
class NeonTxIxBaseFeeInfo:
    # Denominated in gas tokens.
    base_fee_paid: int

    _Default: ClassVar[NeonTxIxBaseFeeInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(base_fee_paid=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.base_fee_paid == 0


@dataclass(frozen=True)
class NeonTxBlockInfo:
    slot: int
    timestamp: int

    _Default: ClassVar[NeonTxBlockInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(slot=0, timestamp=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.slot == 0

    @cached_method
    def to_string(self) -> str:
        if self.is_empty:
            return str_content_object(self, "Empty")
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


@dataclass(frozen=True)
class NeonTxIxStepInfo:
    step_cnt: int
    total_step_cnt: int

    _Default: ClassVar[NeonTxIxStepInfo | None] = None

    @classmethod
    def default(cls) -> Self:
        if cls._Default is None:
            cls._Default = cls(step_cnt=0, total_step_cnt=0)
        return cls._Default

    @property
    def is_empty(self) -> bool:
        return self.step_cnt == 0


@dataclass
class _NeonTxLogDraft:
    sol_tx_ix: SolTxIxMetaInfo
    neon_tx_hash: EthTxHash
    root_neon_tx_hash: EthTxHash
    tx_ix_miner: EthAddress
    tx_ix_step: NeonTxIxStepInfo
    tx_ix_gas: NeonTxIxLogGasInfo
    tx_ix_priority_fee: NeonTxIxPriorityFeeInfo
    tx_ix_base_fee: NeonTxIxBaseFeeInfo
    tx_block: NeonTxBlockInfo
    tx_return: NeonTxLogReturnInfo
    tx_event_list: list[_NeonTxEventDraft]
    tx_error_list: list[NeonTxErrorLogInfo]
    is_truncated: bool
    is_already_finalized: bool

    @classmethod
    def from_raw(cls, sol_tx_ix: SolTxIxMetaInfo) -> Self:
        return cls(
            sol_tx_ix=sol_tx_ix,
            neon_tx_hash=EthTxHash.default(),
            root_neon_tx_hash=EthTxHash.default(),
            tx_ix_miner=EthAddress.default(),
            tx_ix_step=NeonTxIxStepInfo.default(),
            tx_ix_gas=NeonTxIxLogGasInfo.default(),
            tx_ix_priority_fee=NeonTxIxPriorityFeeInfo.default(),
            tx_ix_base_fee=NeonTxIxBaseFeeInfo.default(),
            tx_block=NeonTxBlockInfo.default(),
            tx_return=NeonTxLogReturnInfo.default(),
            tx_event_list=list(),
            tx_error_list=list(),
            is_truncated=False,
            is_already_finalized=False,
        )

    def to_clean_copy(self) -> NeonTxLogInfo:
        if self.tx_event_list:
            if self.neon_tx_hash.is_empty:
                _LOG.error("failed to find %s in the log", _NeonEvmHashLogDecoder.Name)
            # if self.tx_ix_gas.is_empty:
            #     _LOG.debug("failed to find %s in the log", _NeonEvmGasLogDecoder.name)

        return NeonTxLogInfo(
            neon_tx_hash=self.neon_tx_hash,
            root_neon_tx_hash=self.root_neon_tx_hash,
            tx_ix_miner=self.tx_ix_miner,
            tx_ix_step=self.tx_ix_step,
            tx_ix_gas=self.tx_ix_gas,
            tx_ix_priority_fee=self.tx_ix_priority_fee,
            tx_ix_base_fee=self.tx_ix_base_fee,
            tx_block=self.tx_block,
            tx_return=self.tx_return,
            tx_event_list=[e.to_clean_copy(self) for e in self.tx_event_list],
            tx_error_list=self.tx_error_list,
            is_truncated=self.is_truncated,
            is_already_finalized=self.is_already_finalized,
        )


@dataclass
class _NeonTxEventDraft:
    event_type: NeonTxEventModel.Type
    is_hidden: bool

    address: bytes
    topic_list: list[bytes]
    data: bytes

    @classmethod
    def from_raw(
        cls,
        event_type: NeonTxEventModel.Type,
        is_hidden: bool,
        address: bytes,
        topic_list: list[bytes],
        data: bytes,
    ) -> Self:
        return cls(
            event_type=event_type,
            is_hidden=is_hidden,
            address=address,
            topic_list=topic_list,
            data=data,
        )

    def to_clean_copy(self, log: _NeonTxLogDraft) -> NeonTxEventModel:
        return NeonTxEventModel(
            event_type=self.event_type,
            is_hidden=self.is_hidden,
            address=self.address,
            topic_list=self.topic_list,
            data=self.data,
            sol_tx_sig=log.sol_tx_ix.sol_tx_sig,
            sol_ix_idx=log.sol_tx_ix.sol_ix_idx,
            sol_inner_ix_idx=log.sol_tx_ix.sol_inner_ix_idx,
            neon_tx_hash=log.neon_tx_hash,
            total_gas_used=log.tx_ix_gas.total_gas_used,
            total_step_cnt=log.tx_ix_step.total_step_cnt,
            # default:
            is_reverted=False,
            event_level=0,
            event_order=0,
            block_hash=EthBlockHash.default(),
            slot=0,
            neon_tx_idx=0,
            block_log_idx=None,
            neon_tx_log_idx=None,
        )


def _to_b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


class _NeonEvmLogDecoder(abc.ABC):
    _Key: ClassVar[str | None] = None
    Name: ClassVar[str]

    @classmethod
    @abc.abstractmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None: ...

    @classmethod
    def get_key(cls) -> str:
        if not cls._Key:
            cls._Key = _to_b64(cls.Name)
        return cls._Key

    @classmethod
    def _bytes_from_b64(cls, s: str) -> bytes | None:
        try:
            return base64.b64decode(s)
        except BaseException as e:
            _LOG.error("failed to decode %s: %s", cls.Name, str(e))
            return None

    @classmethod
    def _fixed_bytes_from_b64(cls, s: str, expected_len: int) -> bytes | None:
        if (bs := cls._bytes_from_b64(s)) is None:
            return None
        elif len(bs) != expected_len:
            _LOG.error("failed to decode %s: %s", cls.Name, f"expected {expected_len} bytes, got {len(bs)}")
            return None
        return bs

    @classmethod
    def _utf8_from_b64(cls, s: str) -> str | None:
        if (bs := cls._bytes_from_b64(s)) is None:
            return None

        try:
            return bs.decode("utf-8")
        except BaseException as e:
            _LOG.error("failed to decode %s: %s", cls.Name, str(e))
            return None

    @classmethod
    def _int_from_b64(cls, s: str, byteorder: Literal["little", "big"] = "little") -> int | None:
        if (bs := cls._bytes_from_b64(s)) is None:
            return None

        try:
            return int.from_bytes(bs, byteorder)
        except Exception as e:
            _LOG.error("failed to decode %s: %s", cls.Name, str(e))
            return None

    @classmethod
    def _fixed_data_list_len(cls, data_list: Sequence[str], expected_len: int) -> bool:
        if len(data_list) == expected_len:
            return True

        _LOG.error("failed to decode %s: should be %d elements in %s", cls.Name, expected_len, data_list)
        return False

    @classmethod
    def _range_data_list_len(cls, data_list: Sequence[str], min_len: int, max_len: int) -> bool:
        if min_len <= len(data_list) <= max_len:
            return True

        _LOG.error("failed to decode %s: should be (%d, %d) elements in %s", cls.Name, min_len, max_len, data_list)
        return False


class _NeonEvmBlockLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "BLOCK"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """Unpack block info"""
        if not cls._fixed_data_list_len(data_list, 2):
            return
        elif (slot := cls._int_from_b64(data_list[0])) is None:
            return
        elif (timestamp := cls._int_from_b64(data_list[1])) is None:
            return

        log.tx_block = NeonTxBlockInfo(slot=slot, timestamp=timestamp)


class _NeonEvmReturnLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "RETURN"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """Unpacks base64-encoded return data"""
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif log.tx_ix_gas.is_empty:
            _LOG.error("failed to decode %s: fail to get total used gas", cls.Name)
            return
        elif (raw_exit_status := cls._int_from_b64(data_list[0])) is None:
            return

        exit_status = 0x1 if raw_exit_status < 0xD0 else 0x0

        log.tx_return = NeonTxLogReturnInfo(
            event_type=NeonTxEventModel.Type.Return,
            total_gas_used=log.tx_ix_gas.total_gas_used,
            status=exit_status,
        )


class _NeonEvmGasLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "GAS"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """GAS <32 bytes le iteration gas> <32 bytes le total gas>"""
        if not cls._fixed_data_list_len(data_list, 2):
            return
        elif (gas_used := cls._int_from_b64(data_list[0])) is None:
            return
        elif (total_gas_used := cls._int_from_b64(data_list[1])) is None:
            return

        log.tx_ix_gas = NeonTxIxLogGasInfo(gas_used=gas_used, total_gas_used=total_gas_used)


class _NeonEvmPriorityFeeLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "PRIORITYFEE"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """PRIORITYFEE <32 bytes le priority fee as paid by the user>"""
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (fee_paid := cls._int_from_b64(data_list[0])) is None:
            return

        log.tx_ix_priority_fee = NeonTxIxPriorityFeeInfo(priority_fee_paid=fee_paid)


class _NeonEvmBaseFeeLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "BASEFEE"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """BASEFEE <32 bytes le priority fee as paid by the user>"""
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (fee_paid := cls._int_from_b64(data_list[0])) is None:
            return

        log.tx_ix_base_fee = NeonTxIxBaseFeeInfo(base_fee_paid=fee_paid)


class _NeonEvmStepLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "STEPS"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks number of evm steps:
        STEP <32-bytes-le - the number of iteration EVM steps> <32-bytes-le - the total number of EVM steps>
        """
        if not cls._fixed_data_list_len(data_list, 2):
            return
        elif (step_cnt := cls._int_from_b64(data_list[0])) is None:
            return
        elif (total_step_cnt := cls._int_from_b64(data_list[1])) is None:
            return

        log.tx_ix_step = NeonTxIxStepInfo(step_cnt=step_cnt, total_step_cnt=total_step_cnt)


class _NeonEvmErrorLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "ERROR"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: tuple[str, ...]) -> None:
        """
        Unpacks Neon error data:
        ERROR <32 bytes - code> <bytearray - data> <str - message>
        """
        if not cls._fixed_data_list_len(data_list, 3):
            return
        elif (code := cls._int_from_b64(data_list[0])) is None:
            return
        elif (data := cls._bytes_from_b64(data_list[1])) is None:
            return
        elif (msg := cls._utf8_from_b64(data_list[2])) is None:
            return

        error = NeonTxErrorLogInfo.from_raw(code, data, msg)
        log.tx_error_list.append(error)


class _NeonEvmResetLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "RESET"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks Neon reset of all processed EVM steps:
        RESET
        """
        if not cls._fixed_data_list_len(data_list, 0) is False:
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=NeonTxEventModel.Type.StepReset,
            is_hidden=True,
            address=bytes(),
            topic_list=list(),
            data=bytes(),
        )
        log.tx_event_list.append(event)


class _NeonEvmInvalidRevisionDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "INVALID_REVISION"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks Neon event about changed account:
        INVALID_REVISION Solana-address
        """
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (sol_addr := cls._fixed_bytes_from_b64(data_list[0], 32)) is None:
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=NeonTxEventModel.Type.InvalidRevision,
            is_hidden=True,
            address=bytes(),
            topic_list=list(),
            data=sol_addr,
        )
        log.tx_event_list.append(event)


class _NeonEvmHashLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "HASH"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks Neon transaction hash:
        HASH neon_tx_hash
        """
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (neon_tx_hash := cls._fixed_bytes_from_b64(data_list[0], 32)) is None:
            return

        log.neon_tx_hash = EthTxHash.from_raw(neon_tx_hash)


class _NeonEvmRootHashLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "ROOT_HASH"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks Neon transaction hash:
        ROOT_HASH neon_tx_hash
        """
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (neon_tx_hash := cls._fixed_bytes_from_b64(data_list[0], 32)) is None:
            return

        log.root_neon_tx_hash = EthTxHash.from_raw(neon_tx_hash)


class _NeonEvmMinerDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "MINER"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks the miner's address of the instruction:
        MINER address
        """
        if not cls._fixed_data_list_len(data_list, 1):
            return
        elif (addr := cls._fixed_bytes_from_b64(data_list[0], 20)) is None:
            return

        log.tx_ix_miner = EthAddress.from_raw(addr)


class _NeonEvmEventLogDecoder(_NeonEvmLogDecoder):
    TopicCnt: ClassVar[int]

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks base64-encoded event data:
        LOG0 address [0] data
        LOG1 address [1] topic1 data
        LOG2 address [2] topic1 topic2 data
        LOG3 address [3] topic1 topic2 topic3 data
        LOG4 address [4] topic1 topic2 topic3 topic4 data
        """
        if not cls._range_data_list_len(data_list, cls.TopicCnt + 2,  cls.TopicCnt + 3):
            return
        elif (topic_cnt := cls._int_from_b64(data_list[1], "little")) is None:
            return
        elif topic_cnt != cls.TopicCnt:
            _LOG.error("failed to decode %s: wrong number of topics %s", cls.Name, topic_cnt)
            return
        elif (addr := cls._fixed_bytes_from_b64(data_list[0], 20)) is None:
            return

        topic_list = [cls._bytes_from_b64(data_list[2 + i]) for i in range(cls.TopicCnt)]
        if topic_list.count(None):
            return

        data_idx: Final = 2 + cls.TopicCnt
        if (data := cls._bytes_from_b64(data_list[data_idx]) if data_idx < len(data_list) else bytes()) is None:
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=NeonTxEventModel.Type.Log,
            is_hidden=False,
            address=addr,
            topic_list=topic_list,
            data=data,
        )
        log.tx_event_list.append(event)


class _NeonEvmEventLog0Decoder(_NeonEvmEventLogDecoder):
    Name: ClassVar[str] = "LOG0"
    TopicCnt: ClassVar[int] = 0


class _NeonEvmEventLog1Decoder(_NeonEvmEventLogDecoder):
    Name: ClassVar[str] = "LOG1"
    TopicCnt: ClassVar[int] = 1


class _NeonEvmEventLog2Decoder(_NeonEvmEventLogDecoder):
    Name: ClassVar[str] = "LOG2"
    TopicCnt: ClassVar[int] = 2


class _NeonEvmEventLog3Decoder(_NeonEvmEventLogDecoder):
    Name: ClassVar[str] = "LOG3"
    TopicCnt: ClassVar[int] = 3


class _NeonEvmEventLog4Decoder(_NeonEvmEventLogDecoder):
    Name: ClassVar[str] = "LOG4"
    TopicCnt: ClassVar[int] = 4


class _NeonEvmEnterLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "ENTER"
    _EventDict: Final[dict[str, NeonTxEventModel.Type]] = {
        _to_b64("CALL"): NeonTxEventModel.Type.EnterCall,
        _to_b64("CALLCODE"): NeonTxEventModel.Type.EnterCallCode,
        _to_b64("STATICCALL"): NeonTxEventModel.Type.EnterStaticCall,
        _to_b64("DELEGATECALL"): NeonTxEventModel.Type.EnterDelegateCall,
        _to_b64("CREATE"): NeonTxEventModel.Type.EnterCreate,
        _to_b64("CREATE2"): NeonTxEventModel.Type.EnterCreate2,
    }

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks base64-encoded event data:
        ENTER CALL <20 bytes contract address>
        ENTER CALLCODE <20 bytes contract address>
        ENTER STATICCALL <20 bytes contract address>
        ENTER DELEGATECALL <20 bytes contract address>
        ENTER CREATE <20 bytes contract address>
        ENTER CREATE2 <20 bytes contract address>
        """
        if not cls._fixed_data_list_len(data_list, 2):
            return
        elif not (event_type := cls._EventDict.get(data_list[0], None)):
            type_name = cls._utf8_from_b64(data_list[0])
            _LOG.error("failed to decode %s: wrong type %s", cls.Name, type_name)
            return
        elif (addr := cls._fixed_bytes_from_b64(data_list[1], 20)) is None:
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=event_type,
            is_hidden=True,
            address=addr,
            topic_list=list(),
            data=bytes(),
        )
        log.tx_event_list.append(event)


class _NeonEvmExitLogDecoder(_NeonEvmLogDecoder):
    Name: ClassVar[str] = "EXIT"
    _EventDict: Final[dict[str, NeonTxEventModel.Type]] = {
        _to_b64("STOP"): NeonTxEventModel.Type.ExitStop,
        _to_b64("RETURN"): NeonTxEventModel.Type.ExitReturn,
        _to_b64("SELFDESTRUCT"): NeonTxEventModel.Type.ExitSelfDestruct,
        _to_b64("REVERT"): NeonTxEventModel.Type.ExitRevert,
        _to_b64("SENDALL"): NeonTxEventModel.Type.ExitSendAll,
    }

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, data_list: Sequence[str]) -> None:
        """
        Unpacks base64-encoded event data:
        EXIT STOP
        EXIT RETURN
        EXIT SELFDESTRUCT
        EXIT REVERT data
        """
        if not cls._range_data_list_len(data_list, 1, 2):
            return
        elif (event_type := cls._EventDict.get(data_list[0], None)) is None:
            type_name = cls._utf8_from_b64(data_list[0])
            _LOG.error("failed to decode %s: wrong type %s", cls.Name, type_name)
            return
        elif (data := cls._bytes_from_b64(data_list[1]) if len(data_list) == 2 else bytes()) is None:
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=event_type,
            is_hidden=True,
            address=bytes(),
            data=data,
            topic_list=list(),
        )
        log.tx_event_list.append(event)


class NeonEvmLogDecoder:
    _StartLine: Final[str] = "Program data: "
    _ReData: Final[re.Pattern] = re.compile(r"^Program data: (.+)$")
    _LogTruncatedMsg: Final[str] = "Log truncated"
    _IsAlreadyFinalizedMsg: Final[str] = "Program log: Storage Account is finalized"

    _LogDecoderDict: dict[str, type[_NeonEvmLogDecoder]] = {
        cls.get_key(): cls
        for cls in (
            _NeonEvmHashLogDecoder,
            _NeonEvmRootHashLogDecoder,
            _NeonEvmMinerDecoder,
            _NeonEvmResetLogDecoder,
            _NeonEvmInvalidRevisionDecoder,
            _NeonEvmStepLogDecoder,
            _NeonEvmBlockLogDecoder,
            _NeonEvmReturnLogDecoder,
            _NeonEvmEnterLogDecoder,
            _NeonEvmExitLogDecoder,
            _NeonEvmGasLogDecoder,
            _NeonEvmPriorityFeeLogDecoder,
            _NeonEvmBaseFeeLogDecoder,
            _NeonEvmErrorLogDecoder,
            # event logs:
            _NeonEvmEventLog0Decoder,
            _NeonEvmEventLog1Decoder,
            _NeonEvmEventLog2Decoder,
            _NeonEvmEventLog3Decoder,
            _NeonEvmEventLog4Decoder,
        )
    }

    @classmethod
    def _find_decoder(cls, line: str) -> tuple[type[_NeonEvmLogDecoder] | None, Sequence[str]]:
        if not line.startswith(cls._StartLine):
            return None, tuple()

        try:
            match = cls._ReData.match(line)
        except BaseException as e:
            _LOG.error("failed to decode %s: %s", line, e)
            return None, tuple()

        if match is None:
            return None, tuple()

        tail: str = match.group(1)
        data_list: Sequence[str] = tuple(tail.split())
        if len(data_list) < 1:
            return None, tuple()

        if not (decoder := cls._LogDecoderDict.get(data_list[0], None)):
            return None, tuple()

        return decoder, data_list[1:]

    @classmethod
    def decode(cls, log_list: Sequence[str], sol_tx_ix=SolTxIxMetaInfo.default()) -> NeonTxLogInfo:
        """Extracts Neon transaction events from Solana transaction receipt"""

        log = _NeonTxLogDraft.from_raw(sol_tx_ix)
        for msg in log_list:
            if msg == cls._LogTruncatedMsg:
                log.is_truncated = True
                continue
            elif msg == cls._IsAlreadyFinalizedMsg:
                log.is_already_finalized = True
                continue

            _LogDecoder, data_list = cls._find_decoder(msg)
            if _LogDecoder:
                _LogDecoder.decode(log, data_list)

        return log.to_clean_copy()

    @classmethod
    def safe_decode(cls, log_list: Sequence[str], sol_tx_ix=SolTxIxMetaInfo.default()) -> NeonTxLogInfo | None:
        try:
            return cls.decode(log_list, sol_tx_ix)
        except (BaseException,):
            return None

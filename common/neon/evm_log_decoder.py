from __future__ import annotations

import abc
import base64
import enum
import logging
import re
from dataclasses import dataclass
from typing import Final, Sequence, Annotated

from eth_bloom import BloomFilter
from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

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
from ..utils.cached import cached_property
from ..utils.pydantic import BaseModel

_LOG = logging.getLogger(__name__)


class NeonTxEventModelType(enum.IntEnum):
    Log = 1

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
class NeonTxLogInfo:
    neon_tx_hash: EthTxHash
    tx_ix_miner: EthAddress
    tx_ix_step: NeonTxIxStepInfo
    tx_ix_gas: NeonTxIxLogGasInfo
    tx_return: NeonTxLogReturnInfo
    tx_event_list: list[NeonTxEventModel]
    is_truncated: bool
    is_already_finalized: bool


@dataclass(frozen=True)
class NeonTxLogReturnInfo:
    event_type: NeonTxEventModel.Type
    total_gas_used: int
    status: int = 0

    @classmethod
    def default(cls) -> Self:
        return cls(event_type=NeonTxEventModel.Type.Lost, total_gas_used=0, status=0)

    @property
    def is_empty(self) -> bool:
        return self.total_gas_used == 0


@dataclass(frozen=True)
class NeonTxIxLogGasInfo:
    gas_used: int
    total_gas_used: int

    @classmethod
    def default(cls) -> Self:
        return cls(gas_used=0, total_gas_used=0)

    @property
    def is_empty(self) -> bool:
        return self.gas_used == 0


@dataclass(frozen=True)
class NeonTxIxStepInfo:
    step_cnt: int
    total_step_cnt: int

    @classmethod
    def default(cls) -> Self:
        return cls(step_cnt=0, total_step_cnt=0)

    @property
    def is_empty(self) -> bool:
        return self.step_cnt == 0


@dataclass
class _NeonTxLogDraft:
    sol_tx_ix: SolTxIxMetaInfo
    neon_tx_hash: EthTxHash
    tx_ix_miner: EthAddress
    tx_ix_step: NeonTxIxStepInfo
    tx_ix_gas: NeonTxIxLogGasInfo
    tx_return: NeonTxLogReturnInfo
    tx_event_list: list[_NeonTxEventDraft]
    is_truncated: bool
    is_already_finalized: bool

    @classmethod
    def from_raw(cls, sol_tx_ix: SolTxIxMetaInfo) -> Self:
        return cls(
            sol_tx_ix=sol_tx_ix,
            neon_tx_hash=EthTxHash.default(),
            tx_ix_miner=EthAddress.default(),
            tx_ix_step=NeonTxIxStepInfo.default(),
            tx_ix_gas=NeonTxIxLogGasInfo.default(),
            tx_return=NeonTxLogReturnInfo.default(),
            tx_event_list=list(),
            is_truncated=False,
            is_already_finalized=False,
        )

    def to_clean_copy(self) -> NeonTxLogInfo:
        if self.tx_event_list:
            if self.neon_tx_hash.is_empty:
                _LOG.error("failed to find %s in the log", _NeonEvmHashLogDecoder.name)
            if self.tx_ix_gas.is_empty:
                _LOG.error("failed to find %s in the log", _NeonEvmGasLogDecoder.name)

        return NeonTxLogInfo(
            neon_tx_hash=self.neon_tx_hash,
            tx_ix_miner=self.tx_ix_miner,
            tx_ix_step=self.tx_ix_step,
            tx_ix_gas=self.tx_ix_gas,
            tx_return=self.tx_return,
            tx_event_list=[e.to_clean_copy(self) for e in self.tx_event_list],
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


class _NeonEvmLogDecoder(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def decode(cls, log: _NeonTxLogDraft, name: str, data_list: tuple[str, ...]) -> None: ...


class _NeonEvmReturnLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "RETURN"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """Unpacks base64-encoded return data"""
        if not log.tx_return.is_empty:
            _LOG.error("%s is already exist!", cls.name)
            return
        elif len(data_list) < 1:
            _LOG.error("failed to decode %s: less then 1 elements in %s", cls.name, data_list)
            return

        bs = base64.b64decode(data_list[0])
        exit_status = int.from_bytes(bs, "little")
        exit_status = 0x1 if exit_status < 0xD0 else 0x0

        if log.tx_ix_gas.is_empty:
            _LOG.error("Failed to decode %s: fail to get total used gas", cls.name)
            return

        log.tx_return = NeonTxLogReturnInfo(
            event_type=NeonTxEventModel.Type.Return,
            total_gas_used=log.tx_ix_gas.total_gas_used,
            status=exit_status,
        )


class _NeonEvmGasLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "GAS"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """GAS <32 bytes le iteration gas> <32 bytes le total gas>"""
        if not log.tx_ix_gas.is_empty:
            _LOG.error("%s is already exist!", cls.name)
            return
        elif len(data_list) != 2:
            _LOG.error("failed to decode %s: should be 1 element in %s", cls.name, data_list)
            return

        bs = base64.b64decode(data_list[0])
        gas_used = int.from_bytes(bs, "little")

        bs = base64.b64decode(data_list[1])
        total_gas_used = int.from_bytes(bs, "little")

        log.tx_ix_gas = NeonTxIxLogGasInfo(gas_used=gas_used, total_gas_used=total_gas_used)


class _NeonEvmStepLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "STEPS"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks number of evm steps:
        STEP <32-bytes-le - the number of iteration EVM steps> <32-bytes-le - the total number of EVM steps>
        """
        if not log.tx_ix_step.is_empty:
            _LOG.error("%s is already exist!", cls.name)
            return
        elif len(data_list) != 2:
            _LOG.error("failed to decode %s: should be 1 element in %s", cls.name, data_list)
            return

        bs = base64.b64decode(data_list[1])
        total_step_cnt = int.from_bytes(bs, "little")

        bs = base64.b64decode(data_list[0])
        step_cnt = int.from_bytes(bs, "little")

        log.tx_ix_step = NeonTxIxStepInfo(step_cnt=step_cnt, total_step_cnt=total_step_cnt)


class _NeonEvmHashLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "HASH"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks Neon transaction hash:
        HASH neon_tx_hash
        """
        if not log.neon_tx_hash.is_empty:
            _LOG.error("%s is already exist!", cls.name)
            return
        elif len(data_list) != 1:
            _LOG.error("failed to decode %s: should be 1 element in %s", cls.name, data_list)
            return

        neon_tx_hash = base64.b64decode(data_list[0])
        if len(neon_tx_hash) != 32:
            _LOG.error("failed to decode %s: wrong hash length %s", cls.name, len(neon_tx_hash))
            return

        log.neon_tx_hash = EthTxHash.from_raw(neon_tx_hash)


class _NeonEvmMinerDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "MINER"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks address of the miner of the instruction:
        MINER address
        """
        if len(data_list) != 1:
            _LOG.error("failed to decode %s: should 2 elements in %s, %s", cls.name, len(data_list), data_list)
            return

        address = base64.b64decode(data_list[0])
        if len(address) != 20:
            _LOG.error("failed to decode %s: address has wrong length %s", cls.name, len(address))
            return

        log.tx_ix_miner = EthAddress.from_raw(address)


class _NeonEvmEventLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "LOG"

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks base64-encoded event data:
        LOG0 address [0] data
        LOG1 address [1] topic1 data
        LOG2 address [2] topic1 topic2 data
        LOG3 address [3] topic1 topic2 topic3 data
        LOG4 address [4] topic1 topic2 topic3 topic4 data
        """

        if len(data_list) < 3:
            _LOG.error("failed to decode %s: less 3 elements in %s", name, data_list)
            return

        bs = base64.b64decode(data_list[1])
        topic_cnt = int.from_bytes(bs, "little")
        if topic_cnt != int(name[-1:]):
            _LOG.error("failed to decode %s: wrong number of topics %s", name, topic_cnt)
            return

        address = base64.b64decode(data_list[0])
        topic_list = [base64.b64decode(data_list[2 + i]) for i in range(topic_cnt)]

        data_index = 2 + topic_cnt
        data = base64.b64decode(data_list[data_index]) if data_index < len(data_list) else bytes()

        event = _NeonTxEventDraft.from_raw(
            event_type=NeonTxEventModel.Type.Log, is_hidden=False, address=address, topic_list=topic_list, data=data
        )
        log.tx_event_list.append(event)


class _NeonEvmEnterLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "ENTER"
    _event_dict: Final[dict[str, NeonTxEventModel.Type]] = {
        "CALL": NeonTxEventModel.Type.EnterCall,
        "CALLCODE": NeonTxEventModel.Type.EnterCallCode,
        "STATICCALL": NeonTxEventModel.Type.EnterStaticCall,
        "DELEGATECALL": NeonTxEventModel.Type.EnterDelegateCall,
        "CREATE": NeonTxEventModel.Type.EnterCreate,
        "CREATE2": NeonTxEventModel.Type.EnterCreate2,
    }

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks base64-encoded event data:
        ENTER CALL <20 bytes contract address>
        ENTER CALLCODE <20 bytes contract address>
        ENTER STATICCALL <20 bytes contract address>
        ENTER DELEGATECALL <20 bytes contract address>
        ENTER CREATE <20 bytes contract address>
        ENTER CREATE2 <20 bytes contract address>
        """
        if len(data_list) != 2:
            _LOG.error("failed to decode %s: should 2 elements in %s, %s", cls.name, len(data_list), data_list)
            return

        type_name = str(base64.b64decode(data_list[0]), "utf-8")
        if not (event_type := cls._event_dict.get(type_name, None)):
            _LOG.error("failed to decode %s: wrong type %s", cls.name, type_name)
            return

        address = base64.b64decode(data_list[1])
        if len(address) != 20:
            _LOG.error("failed to decode %s: address has wrong length %s", cls.name, len(address))
            return

        event = _NeonTxEventDraft.from_raw(
            event_type=event_type, is_hidden=True, address=address, topic_list=list(), data=bytes()
        )
        log.tx_event_list.append(event)


class _NeonEvmExitLogDecoder(_NeonEvmLogDecoder):
    name: Final[str] = "EXIT"
    _event_dict: Final[dict[str, NeonTxEventModel.Type]] = {
        "STOP": NeonTxEventModel.Type.ExitStop,
        "RETURN": NeonTxEventModel.Type.ExitReturn,
        "SELFDESTRUCT": NeonTxEventModel.Type.ExitSelfDestruct,
        "REVERT": NeonTxEventModel.Type.ExitRevert,
        "SENDALL": NeonTxEventModel.Type.ExitSendAll,
    }

    @classmethod
    def decode(cls, log: _NeonTxLogDraft, _name: str, data_list: tuple[str, ...]) -> None:
        """
        Unpacks base64-encoded event data:
        EXIT STOP
        EXIT RETURN
        EXIT SELFDESTRUCT
        EXIT REVERT data
        """
        if len(data_list) < 1:
            _LOG.error(
                "Failed to decode %s: should be less that 1 element in %s, %s",
                cls.name,
                len(data_list),
                data_list,
            )
            return

        type_name = str(base64.b64decode(data_list[0]), "utf-8")
        if (event_type := cls._event_dict.get(type_name, None)) is None:
            _LOG.error("failed to decode %s: wrong type %s", cls.name, type_name)
            return

        data = bytes()
        if len(data_list) > 1:
            data = base64.b64decode(data_list[1])

        event = _NeonTxEventDraft.from_raw(
            event_type=event_type, is_hidden=True, address=bytes(), data=data, topic_list=list()
        )
        log.tx_event_list.append(event)


class NeonEvmLogDecoder:
    _re_data: Final[re.Pattern] = re.compile(r"^Program data: (.+)$")
    _log_truncated_msg: Final[str] = "Log truncated"
    _is_already_finalized_msg: Final[str] = "Program log: Storage Account is finalized"

    _log_decoder_dict: dict[str, type[_NeonEvmLogDecoder]] = {
        _NeonEvmHashLogDecoder.name: _NeonEvmHashLogDecoder,
        _NeonEvmMinerDecoder.name: _NeonEvmMinerDecoder,
        _NeonEvmStepLogDecoder.name: _NeonEvmStepLogDecoder,
        _NeonEvmReturnLogDecoder.name: _NeonEvmReturnLogDecoder,
        _NeonEvmEnterLogDecoder.name: _NeonEvmEnterLogDecoder,
        _NeonEvmExitLogDecoder.name: _NeonEvmExitLogDecoder,
        _NeonEvmGasLogDecoder.name: _NeonEvmGasLogDecoder,
        # event logs:
        _NeonEvmEventLogDecoder.name + "0": _NeonEvmEventLogDecoder,
        _NeonEvmEventLogDecoder.name + "1": _NeonEvmEventLogDecoder,
        _NeonEvmEventLogDecoder.name + "2": _NeonEvmEventLogDecoder,
        _NeonEvmEventLogDecoder.name + "3": _NeonEvmEventLogDecoder,
        _NeonEvmEventLogDecoder.name + "4": _NeonEvmEventLogDecoder,
    }

    def _decode_mnemonic(self, line: str) -> tuple[str, tuple[str, ...]]:
        match = self._re_data.match(line)
        if match is None:
            return "", tuple()

        tail: str = match.group(1)
        data_list: tuple[str, ...] = tuple(tail.split())
        if len(data_list) < 2:
            return "", tuple()

        mnemonic = str(base64.b64decode(data_list[0]), "utf-8")
        return mnemonic, data_list[1:]

    def decode(self, sol_tx_ix: SolTxIxMetaInfo, log_iter: Sequence[str]) -> NeonTxLogInfo:
        """Extracts Neon transaction events from Solana transaction receipt"""

        log = _NeonTxLogDraft.from_raw(sol_tx_ix)
        for msg in log_iter:
            if msg == self._log_truncated_msg:
                log.is_truncated = True
                continue
            elif msg == self._is_already_finalized_msg:
                log.is_already_finalized = True
                continue

            name, data_list = self._decode_mnemonic(msg)
            if not name:
                continue

            _LogDecoder: type[_NeonEvmLogDecoder] | None = self._log_decoder_dict.get(name, None)
            if _LogDecoder is not None:
                _LogDecoder.decode(log, name, data_list)
            elif _LogDecoder is None:
                _LOG.warning("no decoder for %s %s", name, len(data_list))

        return log.to_clean_copy()

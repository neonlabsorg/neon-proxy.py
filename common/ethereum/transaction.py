from __future__ import annotations

import abc
import logging
from enum import IntEnum
from typing import Final

import eth_keys
import rlp
from eth_hash.auto import keccak
from rlp.sedes import Binary, CountableList, List as ListClass
from typing_extensions import Self

from .errors import EthError
from ..utils.cached import cached_property, cached_method
from ..utils.format import hex_to_bytes, hex_to_int

_LOG = logging.getLogger(__name__)


class EthTxType(IntEnum):
    Legacy = 0x00
    # AccessList = 1 is yet to be supported.
    DynamicGas = 0x02

    @classmethod
    def from_raw(cls, value: EthTxType | int | str | None) -> EthTxType:
        if isinstance(value, cls):
            return value

        try:
            if isinstance(value, str):
                value = hex_to_int(value)

            return cls(value)
        except (BaseException,):
            _LOG.error("unknown EthTxType %s", value)
            return cls.Legacy

    @classmethod
    def is_dynamic_gas_tx(cls, value: int | EthTxType) -> bool:
        return value == cls.DynamicGas

    @classmethod
    def is_legacy_tx(cls, value: int | EthTxType) -> bool:
        return value == cls.Legacy


class _FromAddressMixin(abc.ABC):
    v: int
    r: int
    s: int

    _null_address: Final[bytes] = b"\xff" * 20
    _secpk1n: Final[int] = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    def _calc_from_address(self) -> bytes:
        if (self.r == 0) and (self.s == 0):
            return self._null_address

        if self.r >= self._secpk1n or self.s >= self._secpk1n or self.r == 0 or self.s == 0:
            raise EthError(f"Invalid signature values: r={self.r} s={self.s}!")

        try:
            sig_hash = keccak(self._unsigned_msg_impl())
            sig = self._sig_impl()
            pub = sig.recover_public_key_from_msg_hash(sig_hash)
        except (BaseException,):
            raise EthError("Invalid signature")

        return pub.to_canonical_address()

    @abc.abstractmethod
    def _unsigned_msg_impl(self) -> bytes: ...

    @abc.abstractmethod
    def _sig_impl(self) -> eth_keys.keys.Signature: ...


class _EthNoChainLegacyTxPayload(rlp.Serializable):
    nonce: int
    gas_price: int
    gas_limit: int
    to_address: bytes
    value: int
    call_data: bytes

    fields = (
        ("nonce", rlp.codec.big_endian_int),
        ("gas_price", rlp.codec.big_endian_int),
        ("gas_limit", rlp.codec.big_endian_int),
        ("to_address", rlp.codec.binary),
        ("value", rlp.codec.big_endian_int),
        ("call_data", rlp.codec.binary),
    )

    @classmethod
    def from_raw(cls, s: bytes) -> Self:
        return rlp.decode(s, cls)


class _EthLegacyTxPayload(rlp.Serializable, _FromAddressMixin):
    nonce: int
    gas_price: int
    gas_limit: int
    to_address: bytes
    value: int
    call_data: bytes

    fields: Final[tuple] = (
        ("nonce", rlp.codec.big_endian_int),
        ("gas_price", rlp.codec.big_endian_int),
        ("gas_limit", rlp.codec.big_endian_int),
        ("to_address", rlp.codec.binary),
        ("value", rlp.codec.big_endian_int),
        ("call_data", rlp.codec.binary),
        ("v", rlp.codec.big_endian_int),
        ("r", rlp.codec.big_endian_int),
        ("s", rlp.codec.big_endian_int),
    )

    max_fee_per_gas: Final[int | None] = None
    max_priority_fee_per_gas: Final[int | None] = None

    @classmethod
    def from_raw(cls, s: bytes) -> Self:
        try:
            return rlp.decode(s, cls)
        except rlp.exceptions.ObjectDeserializationError as exc:
            if (not exc.list_exception) or (len(exc.list_exception.serial) != 6):
                raise

            tx = _EthNoChainLegacyTxPayload.from_raw(s)
            return cls._copy_from_nochain_tx(tx)

    @classmethod
    def _copy_from_nochain_tx(cls, nochain_tx: _EthNoChainLegacyTxPayload) -> Self:
        value_list = list()
        for value in nochain_tx:
            value_list.append(value)
        value_list += [0, 0, 0]
        return cls(*value_list)

    @cached_method
    def to_bytes(self) -> bytes:
        return rlp.encode(self)

    @property
    def has_chain_id(self) -> bool:
        return self.chain_id is not None

    @cached_property
    def chain_id(self) -> int | None:
        return EthTx.calc_chain_id(self.v)

    def _unsigned_msg_impl(self) -> bytes:
        if not self.has_chain_id:
            obj = (
                self.nonce,
                self.gas_price,
                self.gas_limit,
                self.to_address,
                self.value,
                self.call_data,
            )
        else:
            obj = (
                self.nonce,
                self.gas_price,
                self.gas_limit,
                self.to_address,
                self.value,
                self.call_data,
                self.chain_id,
                0,
                0,
            )
        return rlp.encode(obj)

    def _sig_impl(self) -> eth_keys.keys.Signature:
        return eth_keys.keys.Signature(vrs=[1 if self.v % 2 == 0 else 0, self.r, self.s])

    @cached_property
    def from_address(self) -> bytes:
        if self.r == 0 and self.s == 0:
            pass
        elif not self.has_chain_id:
            pass
        elif self.v >= 37:
            vee = self.v - self.chain_id * 2 - 8
            assert vee in (27, 28)
        else:
            raise EthError(f"Invalid V value {self.v}")

        return self._calc_from_address()

    @cached_property
    def neon_tx_hash(self) -> bytes:
        obj = (
            self.nonce,
            self.gas_price,
            self.gas_limit,
            self.to_address,
            self.value,
            self.call_data,
            self.v,
            self.r,
            self.s,
        )
        return keccak(rlp.encode(obj))


class _EthDynamicGasTxPayload(rlp.Serializable, _FromAddressMixin):
    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to_address: bytes
    value: int
    call_data: bytes
    access_list: list[tuple[bytes, list[bytes]]]

    gas_price: Final[int | None] = None

    _eth_type: Final[bytes] = EthTxType.DynamicGas.to_bytes(1, byteorder="little")

    fields: Final[tuple] = (
        ("chain_id", rlp.codec.big_endian_int),
        ("nonce", rlp.codec.big_endian_int),
        ("max_priority_fee_per_gas", rlp.codec.big_endian_int),
        ("max_fee_per_gas", rlp.codec.big_endian_int),
        ("gas_limit", rlp.codec.big_endian_int),
        ("to_address", rlp.codec.binary),
        ("value", rlp.codec.big_endian_int),
        ("call_data", rlp.codec.binary),
        # Although it's not used (even Metamask currently does not fully support access lists),
        # the exact rlp sedes structure is in place, so the rlp.decode does not fail.
        (
            "access_list",
            CountableList(
                ListClass(
                    [
                        Binary.fixed_length(20, allow_empty=False),
                        CountableList(Binary.fixed_length(32, allow_empty=False)),
                    ]
                ),
            ),
        ),
        ("v", rlp.codec.big_endian_int),
        ("r", rlp.codec.big_endian_int),
        ("s", rlp.codec.big_endian_int),
    )

    @classmethod
    def from_raw(cls, s: bytes) -> Self:
        return rlp.decode(s, cls)

    @cached_method
    def to_bytes(self) -> bytes:
        return self._eth_type + rlp.encode(self)

    @property
    def has_chain_id(self) -> bool:
        return True

    def _unsigned_msg_impl(self) -> bytes:
        obj = (
            self.chain_id,
            self.nonce,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            self.to_address,
            self.value,
            self.call_data,
            self.access_list,
        )
        return self._eth_type + rlp.encode(obj)

    def _sig_impl(self) -> eth_keys.keys.Signature:
        return eth_keys.keys.Signature(vrs=[self.v, self.r, self.s])

    @cached_property
    def from_address(self) -> bytes:
        return self._calc_from_address()

    @cached_property
    def neon_tx_hash(self) -> bytes:
        obj = (
            self.chain_id,
            self.nonce,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            self.to_address,
            self.value,
            self.call_data,
            self.access_list,
            self.v,
            self.r,
            self.s,
        )
        return keccak(self._eth_type + rlp.encode(obj))


class EthTx:
    def __init__(self, *args, **kwargs):
        tx_type = EthTxType.from_raw(kwargs.pop("type", EthTxType.Legacy))
        self._tx_type = tx_type

        payload: _EthLegacyTxPayload | _EthDynamicGasTxPayload | None
        payload = kwargs.pop("payload", None)
        if payload is not None:
            self._payload = payload
        else:
            if EthTxType.is_legacy_tx(tx_type):
                payload_cls = _EthLegacyTxPayload
            elif EthTxType.is_dynamic_gas_tx(tx_type):
                payload_cls = _EthDynamicGasTxPayload
            else:
                raise ValueError(f"Invalid transaction type specified: {tx_type}")
            self._payload = payload_cls(*args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes | bytearray | str) -> Self:
        if isinstance(s, str):
            s = hex_to_bytes(s)
        elif isinstance(s, bytearray):
            s = bytes(s)

        # Determining transaction type according to the EIP-2718.
        tx_type = s[0]
        if tx_type < 0x7f:
            # Typed transaction.
            if EthTxType.is_legacy_tx(tx_type):
                # Legacy transaction in the envelope form.
                payload_cls = _EthLegacyTxPayload
            elif EthTxType.is_dynamic_gas_tx(tx_type):
                payload_cls = _EthDynamicGasTxPayload
            else:
                raise ValueError(f"Invalid transaction type parsed: {tx_type}")

            # Remove the first byte, so the `s` contains rlp bytes only.
            s = s[1:]
            tx_type = EthTxType.from_raw(tx_type)
        else:
            # Plain legacy transaction (non-enveloped).
            tx_type = EthTxType.Legacy
            payload_cls = _EthLegacyTxPayload

        return cls(type=tx_type, payload=payload_cls.from_raw(s))

    @property
    def tx_type(self) -> EthTxType:
        return self._tx_type

    @property
    def nonce(self) -> int:
        return self._payload.nonce

    @property
    def gas_price(self) -> int | None:
        return self._payload.gas_price

    @property
    def max_priority_fee_per_gas(self) -> int | None:
        return self._payload.max_priority_fee_per_gas

    @property
    def max_fee_per_gas(self) -> int | None:
        return self._payload.max_fee_per_gas

    @property
    def gas_limit(self) -> int:
        return self._payload.gas_limit

    @property
    def value(self) -> int:
        return self._payload.value

    @property
    def call_data(self) -> bytes:
        return self._payload.call_data

    @property
    def to_address(self) -> bytes:
        return self._payload.to_address

    @property
    def v(self) -> int:
        return self._payload.v

    @property
    def r(self) -> int:
        return self._payload.r

    @property
    def s(self) -> int:
        return self._payload.s

    def to_bytes(self) -> bytes:
        return self._payload.to_bytes()  # noqa

    @property
    def has_chain_id(self) -> bool:
        return self._payload.has_chain_id

    @property
    def chain_id(self) -> int | None:
        return self._payload.chain_id

    @staticmethod
    def calc_chain_id(v: int) -> int | None:
        if v in (0, 27, 28):
            return None
        elif v >= 37:
            # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
            # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
            return ((v - 1) // 2) - 17
        else:
            raise EthError(f"Invalid V value {v}")

    @staticmethod
    def calc_contract_address(self) -> bytes | None:
        if self.to_address:
            return None

        contract_addr = rlp.encode((self.from_address, self.nonce))
        return keccak(contract_addr)[-20:]

    @staticmethod
    def has_priority_fee(self) -> bool:
        max_fee_per_gas = self.max_fee_per_gas or 0
        assert max_fee_per_gas >= 0

        max_priority_fee_per_gas = self.max_priority_fee_per_gas or 0
        assert max_priority_fee_per_gas >= 0

        # For metamask case (base_fee_per_gas = 0), we treat it as a legacy transaction.
        # For the general case, we take into account the gas fee parameters set in NeonTx.
        return (max_fee_per_gas - max_priority_fee_per_gas) > 0

    @staticmethod
    def calc_base_fee_per_gas(self) -> int:
        gas_price = self.gas_price or 0
        assert gas_price >= 0

        max_fee_per_gas = self.max_fee_per_gas or 0
        assert max_fee_per_gas >= 0

        max_priority_fee_per_gas = self.max_priority_fee_per_gas or 0
        assert max_priority_fee_per_gas >= 0

        if not max_fee_per_gas:
            return gas_price

        if (base_fee_per_gas := max_fee_per_gas - max_priority_fee_per_gas) > 0:
            return base_fee_per_gas
        return max_fee_per_gas

    @staticmethod
    def calc_cost(self, *, gas_limit: int | None = None, value: int | None = None) -> int:
        if value is None:
            value = self.value
        if gas_limit is None:
            gas_limit = self.gas_limit

        max_fee_per_gas = self.max_fee_per_gas or 0
        gas_price = self.gas_price or 0

        if max_fee_per_gas:
            cost = max_fee_per_gas * gas_limit
        else:
            cost = gas_price * gas_limit
        return cost + value

    @property
    def from_address(self) -> bytes:
        return self._payload.from_address

    @property
    def neon_tx_hash(self) -> bytes:
        return self._payload.neon_tx_hash

    @cached_property
    def contract(self) -> bytes | None:
        return self.calc_contract_address(self)

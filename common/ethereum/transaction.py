from __future__ import annotations

import abc
from typing import Final

import eth_keys
import rlp
from eth_hash.auto import keccak
from typing_extensions import Self

from .errors import EthError
from ..utils.cached import cached_property, cached_method
from ..utils.format import hex_to_bytes


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


class EthTx:
    def __init__(self, *args, **kwargs):
        payload: _EthLegacyTxPayload | None = kwargs.pop("payload", None)
        if payload is not None:
            self._payload = payload
        else:
            payload_cls = _EthLegacyTxPayload
            self._payload = payload_cls(*args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes | bytearray | str) -> Self:
        if isinstance(s, str):
            s = hex_to_bytes(s)
        elif isinstance(s, bytearray):
            s = bytes(s)

        payload_cls = _EthLegacyTxPayload

        return cls(payload=payload_cls.from_raw(s))

    @property
    def nonce(self) -> int:
        return self._payload.nonce

    @property
    def gas_price(self) -> int | None:
        return self._payload.gas_price

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
    def calc_cost(self, *, gas_limit: int | None = None, value: int | None = None) -> int:
        if value is None:
            value = self.value
        if gas_limit is None:
            gas_limit = self.gas_limit

        gas_price = self.gas_price or 0
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

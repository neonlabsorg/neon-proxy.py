from __future__ import annotations

from typing import Final

import rlp
from eth_hash.auto import keccak
from eth_keys import keys as neon_keys
from rlp import Serializable
from rlp.exceptions import ObjectDeserializationError
from typing_extensions import Self

from ..utils.cached import cached_property, cached_method
from ..utils.format import hex_to_bytes


class InvalidEthTx(Exception):
    pass


class EthNoChainTx(Serializable):
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


class EthTx(Serializable):
    nonce: int
    gas_price: int
    gas_limit: int
    to_address: bytes
    value: int
    call_data: bytes
    v: int
    r: int
    s: int

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

    _secpk1n: Final[int] = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    _null_address: Final[bytes] = b"\xff" * 20

    def __init__(self, *args, **kwargs):
        Serializable.__init__(self, *args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes | bytearray | str) -> Self:
        if isinstance(s, str):
            s = hex_to_bytes(s)
        elif isinstance(s, bytearray):
            s = bytes(s)

        try:
            return rlp.decode(s, cls)
        except ObjectDeserializationError as err:
            if (not err.list_exception) or (len(err.list_exception.serial) != 6):
                raise

            tx = EthNoChainTx.from_raw(s)
            return cls._copy_from_nochain_tx(tx)

    @classmethod
    def _copy_from_nochain_tx(cls, nochain_tx: EthNoChainTx) -> Self:
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
        return self.calc_chain_id(self.v)

    @staticmethod
    def calc_chain_id(v: int) -> int | None:
        if v in (0, 27, 28):
            return None
        elif v >= 37:
            # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
            # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
            return ((v - 1) // 2) - 17
        else:
            raise InvalidEthTx(f"Invalid V value {v}")

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

    def _sig_impl(self) -> neon_keys.Signature:
        return neon_keys.Signature(vrs=[1 if self.v % 2 == 0 else 0, self.r, self.s])

    @cached_property
    def from_address(self) -> bytes:
        if self.r == 0 and self.s == 0:
            return self._null_address
        elif not self.has_chain_id:
            pass
        elif self.v >= 37:
            vee = self.v - self.chain_id * 2 - 8
            assert vee in (27, 28)
        else:
            raise InvalidEthTx(f"Invalid V value {self.v}")

        if self.r >= self._secpk1n or self.s >= self._secpk1n or self.r == 0 or self.s == 0:
            raise InvalidEthTx(f"Invalid signature values: r={self.r} s={self.s}!")

        sig_hash = keccak(self._unsigned_msg_impl())
        sig = self._sig_impl()
        pub = sig.recover_public_key_from_msg_hash(sig_hash)

        return pub.to_canonical_address()

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

    @cached_property
    def contract(self) -> bytes | None:
        if self.to_address:
            return None

        contract_addr = rlp.encode((self.from_address, self.nonce))
        return keccak(contract_addr)[-20:]

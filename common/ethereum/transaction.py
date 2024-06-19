from __future__ import annotations

from typing import Annotated, Final

import eth_keys
import rlp
from eth_hash.auto import keccak
from typing_extensions import Self

from .errors import EthError
from ..utils.cached import cached_property, cached_method
from ..utils.format import bytes_to_hex, hex_to_bytes
from ..utils.pydantic import PlainValidator, PlainSerializer


class EthNoChainTx(rlp.Serializable):
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


class EthTx(rlp.Serializable):
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
        rlp.Serializable.__init__(self, *args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes | bytearray | str) -> Self:
        if isinstance(s, cls):
            return s
        elif isinstance(s, str):
            s = hex_to_bytes(s)
        elif isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, dict):
            s = cls.from_dict(s)

        try:
            return rlp.decode(s, cls)
        except rlp.exceptions.ObjectDeserializationError as exc:
            if (not exc.list_exception) or (len(exc.list_exception.serial) != 6):
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

    @classmethod
    def from_dict(cls, d: dict) -> Self:
        return cls(
            nonce=int(d.get("nonce", 0)),
            gas_price=int(d.get("gasPrice", 0)),
            gas_limit=int(d.get("gas", 0)),
            to_address=bytes.fromhex(d.get("to", "")),
            value=int(d.get("value", 0)),
            call_data=bytes.fromhex(d.get("data", "")),
            v=int(d.get("v", 0)),
            r=int(d.get("r", 0)),
            s=int(d.get("s", 0)),
        )

    def to_dict(self) -> dict:
        return {
            "nonce": int(self.nonce),
            "gasPrice": int(self.gas_price),
            "gas": int(self.gas_limit),
            "to": self.to_address,
            "value": int(self.value),
            "data": bytes_to_hex(self.call_data),
        }

    @cached_method
    def to_bytes(self) -> bytes:
        return rlp.encode(self)

    @cached_method
    def to_string(self) -> str:
        return bytes_to_hex(self.to_bytes(), prefix="0x")

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
            raise EthError(f"Invalid V value {v}")

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
            return self._null_address
        elif not self.has_chain_id:
            pass
        elif self.v >= 37:
            vee = self.v - self.chain_id * 2 - 8
            assert vee in (27, 28)
        else:
            raise EthError(f"Invalid V value {self.v}")

        if self.r >= self._secpk1n or self.s >= self._secpk1n or self.r == 0 or self.s == 0:
            raise EthError(f"Invalid signature values: r={self.r} s={self.s}!")

        try:
            sig_hash = keccak(self._unsigned_msg_impl())
            sig = self._sig_impl()
            pub = sig.recover_public_key_from_msg_hash(sig_hash)
        except (BaseException,):
            raise EthError("Invalid signature")

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


EthTxField = Annotated[
    EthTx,
    PlainValidator(EthTx.from_raw),
    PlainSerializer(lambda v: v.to_string(), return_type=str),
]

from __future__ import annotations

from typing import Final, List, Tuple, Union

import eth_keys
import rlp
from eth_hash.auto import keccak
from typing_extensions import Self

from common.utils.pydantic import BaseModel

from .errors import EthError
from ..utils.cached import cached_property, cached_method
from ..utils.format import hex_to_bytes


class EthNoChainLegacyTxPayload(rlp.Serializable):
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

class EthLegacyTxPayload(rlp.Serializable):
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
    def from_raw(cls, s: bytes) -> Self:
        try:
            return rlp.decode(s, cls)
        except rlp.exceptions.ObjectDeserializationError as exc:
            if (not exc.list_exception) or (len(exc.list_exception.serial) != 6):
                raise

            tx = EthNoChainLegacyTxPayload.from_raw(s)
            return cls._copy_from_nochain_tx(tx)

    @classmethod
    def _copy_from_nochain_tx(cls, nochain_tx: EthNoChainLegacyTxPayload) -> Self:
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
        return self._calc_chain_id(self.v)

    @staticmethod
    def _calc_chain_id(v: int) -> int | None:
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
    
class EthDynamicGasTxPayload(rlp.Serializable):
    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to_address: bytes
    value: int
    call_data: bytes
    access_list: List[Tuple[int, List[int]]]
    v: int
    r: int
    s: int

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
        ("access_list", rlp.sedes.lists.CountableList(
            rlp.codec.List(
                [
                    rlp.codec.big_endian_int, 
                    rlp.sedes.lists.CountableList(rlp.codec.big_endian_int)
                ]
        ))),
        ("v", rlp.codec.big_endian_int),
        ("r", rlp.codec.big_endian_int),
        ("s", rlp.codec.big_endian_int),
    )

    _secpk1n: Final[int] = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    _null_address: Final[bytes] = b"\xff" * 20

    def __init__(self, *args, **kwargs):
        rlp.Serializable.__init__(self, *args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes) -> Self:
        return rlp.decode(s, cls)


    @cached_method
    def to_bytes(self) -> bytes:
        return b"\x02" + rlp.encode(self)

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
        return b"\x02" + rlp.encode(obj)

    def _sig_impl(self) -> eth_keys.keys.Signature:
        return eth_keys.keys.Signature(vrs=[self.v, self.r, self.s])

    @cached_property
    def from_address(self) -> bytes:
        if self.r == 0 and self.s == 0:
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
        return keccak(b"\x02" + rlp.encode(obj))

    @cached_property
    def contract(self) -> bytes | None:
        if self.to_address:
            return None

        contract_addr = rlp.encode((self.from_address, self.nonce))
        return keccak(contract_addr)[-20:]

class EthTx:
    type: int
    payload: Union[EthLegacyTxPayload, EthDynamicGasTxPayload]

    def __init__(self, *args, **kwargs):
        tx_type = kwargs.pop("type", 0)
        self.type = tx_type
        
        if (payload := kwargs.pop("payload", None)) is not None:
            self.payload = payload
        else:
            if tx_type == 0:
                payload_cls = EthLegacyTxPayload
            elif tx_type == 2:
                payload_cls = EthDynamicGasTxPayload
            else:
                raise TypeError(f"Invalid transaction type specified: {tx_type}")
            self.payload = payload_cls(*args, **kwargs)

    @classmethod
    def from_raw(cls, s: bytes | bytearray | str) -> Self:
        if isinstance(s, str):
            s = hex_to_bytes(s)
        elif isinstance(s, bytearray):
            s = bytes(s)
        
        # Determining transaction type according to the EIP-2718.
        tx_type = s[0]
        if tx_type <= 0x7f:
            # Typed transaction.
            if tx_type not in (0, 2):
                raise TypeError(f"Invalid transaction type parsed: {tx_type}")
            if tx_type == 0:
                payload_cls = EthLegacyTxPayload
            else:
                payload_cls = EthDynamicGasTxPayload
            # Remove the first byte, so the `s` contains rlp bytes only.
            s = s[1:]
        else:
            # Legacy transaction.
            tx_type = 0
            payload_cls = EthLegacyTxPayload
        
        return cls(type=tx_type, payload=payload_cls.from_raw(s))

    @property
    def nonce(self) -> int:
        return self.payload.nonce
    
    @property
    def gas_price(self) -> int | None:
        if self.type == 0:
            return self.payload.gas_price
        return None
    
    @property
    def max_priority_fee_per_gas(self) -> int | None:
        if self.type == 2:
            return self.payload.max_priority_fee_per_gas
        return None

    @property
    def max_fee_per_gas(self) -> int | None:
        if self.type == 2:
            return self.payload.max_fee_per_gas
        return None

    @property
    def gas_limit(self) -> int:
        return self.payload.gas_limit
    
    @property
    def value(self) -> int:
        return self.payload.value
    
    @property
    def call_data(self) -> bytes:
        return self.payload.call_data
    
    @property
    def to_address(self) -> bytes:
        return self.payload.to_address
    
    @property
    def v(self) -> int:
        return self.payload.v
    
    @property
    def r(self) -> int:
        return self.payload.r
    
    @property
    def s(self) -> int:
        return self.payload.s

    @cached_method
    def to_bytes(self) -> bytes:
        return self.payload.to_bytes()

    @property
    def has_chain_id(self) -> bool:
        return self.payload.has_chain_id

    @cached_property
    def chain_id(self) -> int | None:
        return self.payload.chain_id

    @cached_property
    def from_address(self) -> bytes:
        return self.payload.from_address

    @cached_property
    def neon_tx_hash(self) -> bytes:
        return self.payload.neon_tx_hash

    @cached_property
    def contract(self) -> bytes | None:
        return self.payload.contract

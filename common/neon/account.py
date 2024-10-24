from __future__ import annotations

import random
from typing import Final, Annotated, Union

import eth_account
import eth_keys
import eth_utils
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator
from typing_extensions import Self

from ..ethereum.hash import EthAddress
from .transaction_model import NeonTxModel
from ..utils.cached import cached_method, cached_property
from ..utils.format import bytes_to_hex, hex_to_bytes, hex_to_int


class NeonAccount:
    _empty_address_bytes: Final[bytes] = bytes()
    _empty_chain_id: Final[int] = 0
    NullAddress: Final[str] = "0x"

    def __init__(
        self,
        address: bytes,
        chain_id: int,
        private_key: eth_keys.keys.PrivateKey | None = None,
    ):
        # pydantic.BaseModel validates field types in the constructor
        #  but this is a simple class, that is why the validation is implemented here
        if not isinstance(address, bytes):
            raise ValueError(f"Wrong input type of address: {type(address).__name__}")
        elif chain_id < 0:
            raise ValueError(f"Invalid chain-id given: {chain_id}")
        elif len(address) not in (0, 20):
            raise ValueError(f"Wrong input length of address: {len(address)} not in (0, 20)")
        elif not isinstance(private_key, (type(None), eth_keys.keys.PrivateKey)):
            raise ValueError(f"Wrong input type of private key: {type(private_key).__name__}")

        self._address: Final[bytes] = address
        self._chain_id: Final[int] = chain_id
        self._private_key: Final[eth_keys.keys.PrivateKey | None] = private_key

    def __deepcopy__(self, memo: dict) -> Self:
        """The object is not mutable, so there is no point in creating a copy."""
        memo[id(self)] = self
        return self

    @classmethod
    def default(cls) -> Self:
        return cls(address=cls._empty_address_bytes, chain_id=0, private_key=None)

    @classmethod
    def random(cls, chain_id: int) -> Self:
        data = bytearray([random.randint(0, 255) for _ in range(32)])
        return cls.from_raw(eth_keys.keys.PrivateKey(bytes(data)), chain_id)

    @classmethod
    def from_raw(cls, data: _RawAccount, chain_id: int) -> Self:
        if isinstance(data, cls):
            if chain_id == data.chain_id:
                return data
            return cls(data._address, chain_id, data._private_key)
        elif not data:
            return cls.default()

        address: bytes
        private_key: eth_keys.keys.PrivateKey | None = None

        if isinstance(data, eth_keys.keys.PrivateKey):
            address = data.public_key.to_canonical_address()
            private_key = data
        elif isinstance(data, eth_keys.keys.PublicKey):
            address = data.to_canonical_address()
        elif isinstance(data, EthAddress):
            address = data.to_bytes()
        elif isinstance(data, str):
            address = hex_to_bytes(data)
        elif isinstance(data, bytearray):
            address = bytes(data)
        else:
            address = data

        return cls(address=address, private_key=private_key, chain_id=chain_id)

    @classmethod
    def from_dict(cls, data: _DictAccount | NeonAccount) -> Self:
        if isinstance(data, NeonAccount):
            return data
        elif not data:
            return cls.default()

        address = hex_to_bytes(data["address"])
        chain_id = hex_to_int(data["chain_id"])
        private_key_data = hex_to_bytes(data.get("private_key", None))
        private_key = eth_keys.keys.PrivateKey(private_key_data) if private_key_data else None

        return cls(address=address, chain_id=chain_id, private_key=private_key)

    @classmethod
    def from_private_key(cls, pk_data: str | bytes | eth_keys.keys.PrivateKey, chain_id: int) -> Self:
        if isinstance(pk_data, str):
            pk_data = hex_to_bytes(pk_data)
        if isinstance(pk_data, bytes):
            if len(pk_data) < 32:
                raise ValueError(f"Not enough data for private key: {len(pk_data)}")
            pk_data = eth_keys.keys.PrivateKey(pk_data[:32])
        return cls.from_raw(pk_data, chain_id)

    def to_dict(self: NeonAccount) -> _DictAccount:
        res = dict(
            address=self._to_checksum_address(),
            chain_id=hex(self._chain_id),
        )
        if self._private_key:
            res["private_key"] = self._private_key.to_hex()
        return res

    @property
    def is_empty(self) -> bool:
        return not self._address

    def to_bytes(self, default: bytes | None = bytes()) -> bytes | None:
        return self._address if self._address else default

    @cached_property
    def eth_address(self) -> EthAddress:
        return EthAddress.from_raw(self._address)

    @cached_method
    def to_string(self) -> str:
        return self._to_checksum_address() + ":" + hex(self._chain_id) if not self.is_empty else ""

    def to_address(self, default: str | None = NullAddress) -> str | None:
        return self._to_address() if self._address else default

    @cached_method
    def _to_address(self) -> str:
        return bytes_to_hex(self._address) if self._address else self.NullAddress

    def to_checksum_address(self, default: str | None = NullAddress) -> str | None:
        return self._to_checksum_address() if self._address else default

    @cached_method
    def _to_checksum_address(self) -> str:
        return eth_utils.to_checksum_address(self._address) if self._address else self.NullAddress

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def private_key(self) -> eth_keys.keys.PrivateKey:
        assert self._private_key
        return self._private_key

    def sign_msg(self, data: bytes) -> eth_keys.keys.Signature:
        return self.private_key.sign_msg(data)

    def sign_tx(self, tx: NeonTxModel) -> bytes:
        tx_dict = tx.to_eth_dict()
        tx_dict["chainId"] = self._chain_id
        signed_tx = eth_account.Account.sign_transaction(tx_dict, self.private_key)
        return bytes(signed_tx.raw_transaction)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_method
    def __hash__(self) -> int:
        return hash(tuple([self._address, self._chain_id]))

    def __eq__(self, other: _RawAccount) -> bool:
        if other is self:
            return True
        elif isinstance(other, self.__class__):
            return (self._address, self._chain_id) == (other._address, other._chain_id)
        elif isinstance(other, str):
            return self.to_address() == other.lower()
        elif isinstance(other, (bytes, bytearray)):
            return self._address == bytes(other)
        elif isinstance(other, EthAddress):
            return self._address == other.to_bytes()
        return False


_DictAccount = dict[str, str]
_RawAccount = Union[
    None, str, bytes, bytearray, EthAddress, eth_keys.keys.PublicKey, eth_keys.keys.PrivateKey, NeonAccount
]


# Type for Pydantic, it doesn't do anything, only annotates rules for serialization and deserialization
NeonAccountField = Annotated[
    NeonAccount,
    PlainValidator(NeonAccount.from_dict),
    PlainSerializer(lambda v: v.to_dict(), return_type=_DictAccount),
]

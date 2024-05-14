from __future__ import annotations

from typing import Union

from typing_extensions import Self

from ..ethereum.bin_str import EthBinStr, EthBinStrField
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddressField, EthAddress
from ..ethereum.transaction import EthTx
from ..utils.cached import cached_property, cached_method
from ..utils.format import str_fmt_object
from ..utils.pydantic import BaseModel, HexUIntField


class NeonTxModel(BaseModel):
    tx_type: HexUIntField
    neon_tx_hash: EthTxHashField
    from_address: EthAddressField
    to_address: EthAddressField
    contract: EthAddressField
    nonce: HexUIntField
    gas_price: HexUIntField
    gas_limit: HexUIntField
    value: HexUIntField
    call_data: EthBinStrField
    v: HexUIntField
    r: HexUIntField
    s: HexUIntField

    error: str | None = None

    @classmethod
    def default(cls) -> Self:
        return cls(
            tx_type=0,
            neon_tx_hash=EthTxHash.default(),
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            gas_price=0,
            gas_limit=0,
            value=0,
            call_data=EthBinStr.default(),
            v=0,
            r=0,
            s=0,
            error=None,
        )

    @classmethod
    def from_raw(cls, data: _RawNeonTxModel, *, raise_exception=False) -> Self:
        if isinstance(data, cls):
            return data
        elif data is None:
            return cls.default()
        elif isinstance(data, (str, bytes, bytearray)):
            return cls._from_rlp(data, raise_exception)
        elif isinstance(data, EthTx):
            return cls._from_eth_tx(data)
        elif isinstance(data, dict):
            return cls.from_dict(data)
        elif isinstance(data, EthTxHash):
            return cls._from_tx_hash(data)

        raise ValueError(f"Unsupported input type: {type(data).__name__}")

    @classmethod
    def _from_rlp(cls, data: str | bytes | bytearray, raise_exception: bool) -> Self:
        try:
            tx = EthTx.from_raw(data)
            return cls._from_eth_tx(tx)
        except Exception as exc:
            if raise_exception:
                raise

            return cls(
                error=str(exc),
                #
                tx_type=0,
                neon_tx_hash=EthTxHash.default(),
                from_address=EthAddress.default(),
                to_address=EthAddress.default(),
                contract=EthAddress.default(),
                nonce=0,
                gas_price=0,
                gas_limit=0,
                value=0,
                call_data=EthBinStr.default(),
                v=0,
                r=0,
                s=0,
            )

    @classmethod
    def _from_eth_tx(cls, tx: EthTx) -> Self:
        return cls(
            tx_type=0,
            neon_tx_hash=tx.neon_tx_hash,
            from_address=tx.from_address,
            to_address=tx.to_address,
            contract=tx.contract,
            v=tx.v,
            r=tx.r,
            s=tx.s,
            nonce=tx.nonce,
            gas_price=tx.gas_price,
            gas_limit=tx.gas_limit,
            value=tx.value,
            call_data=tx.call_data,
            error=None,
        )

    @classmethod
    def _from_tx_hash(cls, neon_tx_hash: EthTxHash) -> Self:
        return cls(
            neon_tx_hash=neon_tx_hash,
            # default:
            tx_type=0,
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            gas_price=0,
            gas_limit=0,
            value=0,
            call_data=EthBinStr.default(),
            v=0,
            r=0,
            s=0,
            error=None,
        )

    def to_rlp_tx(self) -> bytes:
        tx = EthTx(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas_limit=self.gas_limit,
            to_address=self.to_address.to_bytes(),
            value=self.value,
            call_data=self.call_data.to_bytes(),
            v=self.v,
            r=self.r,
            s=self.s,
        )

        return tx.to_bytes()

    @property
    def has_chain_id(self) -> bool:
        return self.chain_id is not None

    @cached_property
    def chain_id(self) -> int | None:
        return EthTx.calc_chain_id(self.v)

    @property
    def is_valid(self) -> bool:
        return (not self.from_address.is_empty) and (not self.error)

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self)

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


_RawNeonTxModel = Union[str, bytes, dict, EthTxHash, EthTx, None]

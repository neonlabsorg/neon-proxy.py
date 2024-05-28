from __future__ import annotations

from typing import Union, Any

from typing_extensions import Self

from ..ethereum.bin_str import EthBinStr, EthBinStrField
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddressField, EthAddress
from ..ethereum.transaction import EthTx
from ..utils.cached import cached_method, cached_property
from ..utils.format import str_fmt_object
from ..utils.pydantic import BaseModel, HexUIntField

from pydantic import Field


_TX_MODEL_EXCLUDE_LIST = {
    0: {"max_priority_fee_per_gas", "max_fee_per_gas", "tx_chain_id", "chain_id"},
    2: {"gas_price"},
}


class NeonTxModel(BaseModel):
    tx_type: HexUIntField
    # None for legacy transaction (calculated from v), present for dynamic gas transaction.
    tx_chain_id: HexUIntField | None = Field(default=None, serialization_alias="chain_id")
    neon_tx_hash: EthTxHashField
    from_address: EthAddressField
    to_address: EthAddressField
    contract: EthAddressField
    nonce: HexUIntField
    # Gas price for the legacy transactions.
    gas_price_legacy: HexUIntField | None = Field(default=None, serialization_alias="gas_price")
    # Gas parameters for the Dynamic Gas transactions.
    max_priority_fee_per_gas: HexUIntField | None = Field(default=None)
    max_fee_per_gas: HexUIntField | None = Field(default=None)
    gas_limit: HexUIntField
    value: HexUIntField
    call_data: EthBinStrField
    # Access List is missing, no support yet.
    v: HexUIntField
    r: HexUIntField
    s: HexUIntField

    error: str | None = None

    def model_post_init(self, _ctx: Any) -> None:
        if self.tx_type not in (0, 2):
            raise ValueError("Unsupported transaction type.")
        if self.tx_type == 0:
            if self.gas_price_legacy is None:
                raise ValueError("gas_price is not specified for the Legacy transaction.")
            if self.max_priority_fee_per_gas is not None or self.max_fee_per_gas is not None:
                raise ValueError(
                    "max_priority_fee_per_gas or max_fee_per_gas should be absent for the Legacy transaction."
                )
        else:
            if self.gas_price_legacy is not None:
                raise ValueError("gas_price shouldn't be specified for the Dynamic Gas transaction.")
            if self.max_priority_fee_per_gas is None or self.max_fee_per_gas is None:
                raise ValueError(
                    "max_priority_fee_per_gas or max_fee_per_gas is absent for the Dynamic Gas transaction."
                )

    @classmethod
    def default(cls) -> Self:
        return cls(
            # TODO EIP1559: use tx_type=2 when ready.
            tx_type=0,
            neon_tx_hash=EthTxHash.default(),
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            gas_price_legacy=0,
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
                # TODO EIP1559: use tx_type=2 when ready.
                tx_type=0,
                neon_tx_hash=EthTxHash.default(),
                from_address=EthAddress.default(),
                to_address=EthAddress.default(),
                contract=EthAddress.default(),
                nonce=0,
                gas_price_legacy=0,
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
            tx_type=tx.type,
            tx_chain_id=tx.chain_id,
            neon_tx_hash=tx.neon_tx_hash,
            from_address=tx.from_address,
            to_address=tx.to_address,
            contract=tx.contract,
            v=tx.v,
            r=tx.r,
            s=tx.s,
            nonce=tx.nonce,
            gas_price_legacy=tx.gas_price,
            max_priority_fee_per_gas=tx.max_priority_fee_per_gas,
            max_fee_per_gas=tx.max_fee_per_gas,
            gas_limit=tx.gas_limit,
            value=tx.value,
            call_data=tx.call_data,
            error=None,
        )

    @cached_method
    def _to_eth_tx(self) -> EthTx:
        ctr = dict(
            type=self.tx_type,
            chain_id=self.chain_id,
            nonce=self.nonce,
            gas_price=self.gas_price_legacy,
            max_priority_fee_per_gas=self.max_priority_fee_per_gas,
            max_fee_per_gas=self.max_fee_per_gas,
            gas_limit=self.gas_limit,
            to_address=self.to_address.to_bytes(),
            value=self.value,
            call_data=self.call_data.to_bytes(),
            v=self.v,
            r=self.r,
            s=self.s,
        )
        for pop_field in _TX_MODEL_EXCLUDE_LIST[self.tx_type]:
            ctr.pop(pop_field, None)

        return EthTx(**ctr)

    @classmethod
    def _from_tx_hash(cls, neon_tx_hash: EthTxHash) -> Self:
        return cls(
            neon_tx_hash=neon_tx_hash,
            # TODO EIP1559: use tx_type=2 when ready.
            tx_type=0,
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            gas_price_legacy=0,
            gas_limit=0,
            value=0,
            call_data=EthBinStr.default(),
            v=0,
            r=0,
            s=0,
            error=None,
        )

    def to_rlp_tx(self) -> bytes:
        return self._to_eth_tx().to_bytes()

    def to_eth_dict(self) -> dict:
        return dict(
            nonce=self.nonce,
            gasPrice=self.gas_price,
            gas=self.gas_limit,
            to=self.to_address.to_checksum(),
            value=self.value,
            data=self.call_data.to_string(),
        )

    @property
    def has_chain_id(self) -> bool:
        return self.chain_id is not None

    @cached_property
    def chain_id(self) -> int | None:
        # Chain_id is derived from the v for the legacy transactions.
        if self.tx_type == 0:
            return EthTx.calc_chain_id(self.v)
        # For Dynamic Gas, chain_id is stored as a field.
        return self.tx_chain_id

    @property
    def is_valid(self) -> bool:
        return (not self.from_address.is_empty) and (not self.error)

    @cached_property
    def gas_price(self) -> int:
        if self.tx_type == 0:
            return self.gas_price_legacy
        else:
            # TODO EIP1559: check usage across the code and validate if it's correct.
            return self.max_fee_per_gas

    # Overriding BaseModel to exclude gas price related fields based on transaction type.
    def to_json(self) -> str:
        return self.model_dump_json(exclude=_TX_MODEL_EXCLUDE_LIST[self.tx_type], by_alias=True)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude=_TX_MODEL_EXCLUDE_LIST[self.tx_type], by_alias=True)

    @cached_method
    def to_string(self) -> str:
        # Corresponding cached properties are included in the string representation.
        return str_fmt_object(self, skip_keys={"tx_chain_id", "gas_price_legacy"})

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


_RawNeonTxModel = Union[str, bytes, dict, EthTxHash, EthTx, None]

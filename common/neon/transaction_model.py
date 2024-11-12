from __future__ import annotations

import logging
from typing import Union, Any, ClassVar

from typing_extensions import Self

from ..ethereum.bin_str import EthBinStr, EthBinStrField
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddressField, EthAddress
from ..ethereum.transaction import EthTx, EthTxType
from ..utils.cached import cached_method, cached_property
from ..utils.format import str_fmt_object, hex_to_uint
from ..utils.pydantic import BaseModel, HexUIntField

_LOG = logging.getLogger(__name__)

NeonTxType = EthTxType


class NeonTxModel(BaseModel):
    tx_type: HexUIntField
    # None for legacy transaction (calculated from v), present for dynamic gas transaction.
    chain_id: HexUIntField | None = None
    neon_tx_hash: EthTxHashField = EthTxHash.default()
    from_address: EthAddressField
    to_address: EthAddressField
    contract: EthAddressField = EthAddress.default()
    nonce: HexUIntField
    # Gas price for the legacy transactions.
    gas_price: HexUIntField | None = None
    # Gas parameters for the Dynamic Gas transactions.
    max_priority_fee_per_gas: HexUIntField | None = None
    max_fee_per_gas: HexUIntField | None = None
    gas_limit: HexUIntField
    value: HexUIntField
    call_data: EthBinStrField
    # Access List is missing, no support yet.
    v: HexUIntField = 0
    r: HexUIntField = 0
    s: HexUIntField = 0

    rlp_tx: EthBinStrField = EthBinStr.default()
    error: str | None = None

    _exclude_list_dict: ClassVar[dict] = {
        NeonTxType.Legacy: tuple(
            [
                "chain_id",
                "max_priority_fee_per_gas",
                "max_fee_per_gas",
                "access_list",
            ]
        ),
        NeonTxType.DynamicGas: tuple(["gas_price",]),
    }

    def model_post_init(self, _ctx: Any) -> None:
        _ = NeonTxType(self.tx_type)

        if self.is_legacy_tx:
            if self.gas_price is None:
                raise ValueError("gas_price is not specified for the Legacy transaction.")
            if (self.max_fee_per_gas is not None) or (self.max_priority_fee_per_gas is not None):
                raise ValueError("max_fee_per_gas and max_priority_fee_per_gas should not be present.")
        elif self.is_dynamic_gas_tx:
            if (self.max_priority_fee_per_gas is None) or (self.max_fee_per_gas is None):
                raise ValueError(
                    "max_priority_fee_per_gas or max_fee_per_gas is not specified for the Dynamic Gas transaction."
                )
            if self.gas_price is not None:
                raise ValueError("gas_price should not be present.")
            if self.max_priority_fee_per_gas > self.max_fee_per_gas:
                raise ValueError("max priority fee per gas higher than max fee per gas.")
            if self.chain_id is None:
                raise ValueError("chain_id should be specified for the Dynamic Gas transactions.")

    @classmethod
    def new_empty(
        cls,
        *,
        error: str | None = None,
        neon_tx_hash: EthTxHash = EthTxHash.default(),
    ) -> Self:
        return cls(
            tx_type=NeonTxType.DynamicGas,
            chain_id=0,
            neon_tx_hash=neon_tx_hash,
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            max_fee_per_gas=0,
            max_priority_fee_per_gas=0,
            gas_limit=0,
            value=0,
            call_data=EthBinStr.default(),
            error=error,
        )

    @classmethod
    def default(cls) -> Self:
        return cls.new_empty()

    @classmethod
    def from_raw(
        cls,
        data: _RawNeonTxModel,
        *,
        raise_exception=False,
    ) -> Self:
        if isinstance(data, cls):
            return data
        elif data is None:
            return cls.default()
        elif isinstance(data, (str, bytes, bytearray)):
            return cls._from_rlp(data, raise_exception)
        elif isinstance(data, EthTx):
            return cls._from_eth_tx(data, bytes())
        elif isinstance(data, dict):
            return cls._from_dict(data)
        elif isinstance(data, EthTxHash):
            return cls._from_tx_hash(data)

        raise ValueError(f"Unsupported input type: {type(data).__name__}")

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Self:
        tx_type = NeonTxType.from_raw(data.get("tx_type", NeonTxType.DynamicGas))

        exclude_list = cls._exclude_list_dict.get(tx_type)
        for value in exclude_list:
            data.pop(value, None)

        data["tx_type"] = tx_type

        if NeonTxType.is_legacy_tx(tx_type):
            v = hex_to_uint(data.get("v", 0))
            data["chain_id"] = EthTx.calc_chain_id(v)

        return cls.from_dict(data)

    @classmethod
    def _from_rlp(cls, data: str | bytes | bytearray, raise_exception: bool) -> Self:
        try:
            tx = EthTx.from_raw(data)
            return cls._from_eth_tx(tx, data)
        except Exception as exc:
            if raise_exception:
                raise

            return cls.new_empty(error=str(exc))

    @classmethod
    def _from_eth_tx(cls, tx: EthTx, rlp_tx: bytes) -> Self:
        if not rlp_tx:
            rlp_tx = tx.to_bytes()

        param_dict = dict(
            tx_type=tx.tx_type,
            chain_id=tx.chain_id,
            neon_tx_hash=tx.neon_tx_hash,
            from_address=tx.from_address,
            nonce=tx.nonce,
            to_address=tx.to_address,
            contract=tx.contract,
            call_data=tx.call_data,
            gas_price=tx.gas_price,
            max_priority_fee_per_gas=tx.max_priority_fee_per_gas,
            max_fee_per_gas=tx.max_fee_per_gas,
            gas_limit=tx.gas_limit,
            value=tx.value,
            v=tx.v,
            r=tx.r,
            s=tx.s,
            error=None,
            rlp_tx=rlp_tx,
        )
        return cls.from_dict(param_dict)

    @cached_method
    def _to_eth_tx(self) -> EthTx:
        value_dict = self.to_eth_dict()
        return EthTx(**value_dict)

    @classmethod
    def _from_tx_hash(cls, neon_tx_hash: EthTxHash) -> Self:
        return cls.new_empty(neon_tx_hash=neon_tx_hash)

    @property
    def is_dynamic_gas_tx(self) -> bool:
        return NeonTxType.is_dynamic_gas_tx(self.tx_type)

    @property
    def is_legacy_tx(self) -> bool:
        return NeonTxType.is_legacy_tx(self.tx_type)

    @cached_method
    def to_rlp_tx(self) -> bytes:
        return self.rlp_tx.to_bytes() if not self.rlp_tx.is_empty else self._to_eth_tx().to_bytes()

    def to_eth_dict(self) -> dict:
        value_dict = dict(
            nonce=self.nonce,
            gas_limit=self.gas_limit,
            to_address=self.to_address.to_bytes(),
            value=self.value,
            call_data=self.call_data.to_bytes(),
            r=self.r,
            s=self.s,
            v=self.v,
        )
        if self.is_legacy_tx:
            value_dict["gas_price"] = self.gas_price
        elif self.is_dynamic_gas_tx:
            value_dict.update(
                dict(
                    type=self.tx_type,
                    chain_id=self.chain_id,
                    access_list=list(),
                    max_fee_per_gas=self.max_fee_per_gas,
                    max_priority_fee_per_gas=self.max_priority_fee_per_gas,
                )
            )
        else:
            raise ValueError("Unknown transaction type")
        return value_dict

    @property
    def has_chain_id(self) -> bool:
        return self.chain_id is not None

    @property
    def is_valid(self) -> bool:
        return (not self.from_address.is_empty) and (not self.error)

    @cached_property
    def has_priority_fee(self) -> bool:
        return EthTx.has_priority_fee(self)

    @cached_property
    def base_fee_per_gas(self) -> int:
        return EthTx.calc_base_fee_per_gas(self)

    def calc_cost(self, *, gas_limit: int | None = None, value: int | None = None) -> int:
        return EthTx.calc_cost(self, gas_limit=gas_limit, value=value)

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self, skip_key_list=("rlp_tx",))

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


_RawNeonTxModel = Union[str, bytes, dict, EthTxHash, EthTx, None]

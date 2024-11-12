from __future__ import annotations

from typing import Union, Any

from typing_extensions import Self

from ..ethereum.bin_str import EthBinStr, EthBinStrField
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddressField, EthAddress
from ..ethereum.transaction import EthTx
from ..utils.cached import cached_method
from ..utils.format import str_fmt_object, hex_to_uint
from ..utils.pydantic import BaseModel, HexUIntField


class NeonTxModel(BaseModel):
    tx_type: HexUIntField
    chain_id: HexUIntField | None = None
    neon_tx_hash: EthTxHashField = EthTxHash.default()
    from_address: EthAddressField
    to_address: EthAddressField
    contract: EthAddressField = EthAddress.default()
    nonce: HexUIntField
    gas_price: HexUIntField
    gas_limit: HexUIntField
    value: HexUIntField
    call_data: EthBinStrField
    v: HexUIntField = 0
    r: HexUIntField = 0
    s: HexUIntField = 0

    rlp_tx: EthBinStrField = EthBinStr.default()
    error: str | None = None

    def model_post_init(self, _ctx: Any) -> None:
        if self.gas_price is None:
            raise ValueError("gas_price is not specified for the Legacy transaction.")

    @classmethod
    def new_empty(
        cls,
        *,
        error: str | None = None,
        neon_tx_hash: EthTxHash = EthTxHash.default(),
    ) -> Self:
        return cls(
            tx_type=0,
            chain_id=None,
            neon_tx_hash=neon_tx_hash,
            from_address=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
            gas_price=0,
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
            tx_type=0,
            chain_id=tx.chain_id,
            neon_tx_hash=tx.neon_tx_hash,
            from_address=tx.from_address,
            nonce=tx.nonce,
            to_address=tx.to_address,
            contract=tx.contract,
            call_data=tx.call_data,
            gas_price=tx.gas_price,
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

    @cached_method
    def to_rlp_tx(self) -> bytes:
        return self.rlp_tx.to_bytes() if not self.rlp_tx.is_empty else self._to_eth_tx().to_bytes()

    def to_eth_dict(self) -> dict:
        return dict(
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

    @property
    def has_chain_id(self) -> bool:
        return self.chain_id is not None

    @property
    def is_valid(self) -> bool:
        return (not self.from_address.is_empty) and (not self.error)

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

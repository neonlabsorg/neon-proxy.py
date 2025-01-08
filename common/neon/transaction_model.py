from __future__ import annotations

import logging
from enum import IntEnum
from typing import Union, Any, ClassVar, Annotated

from pydantic import PlainValidator, PlainSerializer
from typing_extensions import Self

from ..ethereum.bin_str import EthBinStr, EthBinStrField
from ..ethereum.hash import EthTxHash, EthTxHashField, EthAddressField, EthAddress
from ..ethereum.transaction import EthTx, EthTxType
from ..solana.pubkey import SolPubKey, SolPubKeyField
from ..solana.signature import SolTxSigField, SolTxSig
from ..utils.cached import cached_method, cached_property
from ..utils.format import str_fmt_object, hex_to_uint, hex_to_int, has_hex_start
from ..utils.pydantic import BaseModel, HexUIntField, DecUIntField

_LOG = logging.getLogger(__name__)

NeonTxType = EthTxType


class NeonSkdTxStatus(IntEnum):
    Failed = 0x00
    Success = 0x01
    Skipped = 0x02
    InProgress = 0x03

    ToStart = 0xE0
    ToSkip = 0xE1
    Destroyed = 0xEF

    NotStarted = 0xFF

    @classmethod
    def from_raw(cls, value: int | str | NeonSkdTxStatus | None) -> Self:
        if isinstance(value, cls):
            return value

        try:
            if isinstance(value, str):
                if has_hex_start(value):
                    value = hex_to_int(value)
                else:
                    name_dict = cls._get_name_dict()
                    return name_dict[value]

            return cls(value)
        except (BaseException,):
            _LOG.debug("bad NeonSkdTree status %s", value)
            return cls.NotStarted

    @classmethod
    def _get_name_dict(cls) -> dict[str, NeonSkdTxStatus]:
        if hasattr(cls, "_name_dict"):
            return getattr(cls, "_name_dict")

        # fmt: off
        _name_dict: dict[str, NeonSkdTxStatus] = {
            item.name: item
            for item in cls.__members__.values()
        }
        # fmt: on
        setattr(cls, "_name_dict", _name_dict)
        return _name_dict


NeonSkdTxStatusField = Annotated[
    NeonSkdTxStatus,
    PlainValidator(NeonSkdTxStatus.from_raw),
    PlainSerializer(lambda v: v.value, return_type=int),
]


class NeonSkdTxModel(BaseModel):
    slot: DecUIntField
    neon_tx_hash: EthTxHashField
    tree_address: SolPubKeyField
    sol_skd_tx_sig: SolTxSigField
    sol_skd_payer: SolPubKeyField
    neon_payer: EthAddressField
    chain_id: DecUIntField
    nonce: DecUIntField
    rlp_tx: EthBinStrField

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self, skip_key_list=tuple(["rlp_tx"]))


class NeonTxModel(BaseModel):
    tx_type: HexUIntField
    # None for legacy transaction (calculated from v), present for dynamic gas transaction.
    chain_id: HexUIntField | None = None
    neon_tx_hash: EthTxHashField = EthTxHash.default()
    from_address: EthAddressField
    # custom value in the case of scheduled txs, in other cases there are the same value with from_address
    payer: EthAddressField
    sol_skd_payer: SolPubKeyField = SolPubKey.default()
    # exists only in scheduled txs
    intent: EthAddressField = EthAddress.default()
    intent_call_data: EthBinStrField = EthBinStr.default()
    to_address: EthAddressField
    contract: EthAddressField = EthAddress.default()
    nonce: HexUIntField
    index: HexUIntField = 0
    # Gas price for the legacy transactions.
    gas_price: HexUIntField = 0
    # Gas parameters for the Dynamic Gas transactions.
    max_priority_fee_per_gas: HexUIntField = 0
    max_fee_per_gas: HexUIntField = 0
    gas_limit: HexUIntField
    value: HexUIntField
    call_data: EthBinStrField
    # Access List is missing, no support yet.
    v: HexUIntField = 0
    r: HexUIntField = 0
    s: HexUIntField = 0
    # Solana signature
    sol_skd_tx_sig: SolTxSigField = SolTxSig.default()

    rlp_tx: EthBinStrField = EthBinStr.default()
    error: str | None = None

    _exclude_list_dict: ClassVar[dict] = {
        NeonTxType.Legacy: tuple(
            [
                "chain_id",
                "max_priority_fee_per_gas",
                "max_fee_per_gas",
                "access_list",
                "payer",
                "index",
                "intent",
                "intent_call_data",
            ]
        ),
        NeonTxType.DynamicGas: tuple(
            [
                "gas_price",
                "payer",
                "index",
                "intent",
                "intent_call_data",
            ]
        ),
        NeonTxType.Scheduled: tuple(["gas_price", "access_list"]),
    }

    def model_post_init(self, _ctx: Any) -> None:
        _ = NeonTxType(self.tx_type)

        if not self.is_scheduled_tx:
            if self.index:
                raise ValueError("index should not be present.")
            if not self.intent.is_empty:
                raise ValueError("intent should not be present.")
            if not self.intent_call_data.is_empty:
                raise ValueError("intent_call_data should not be present.")
            if not self.sol_skd_tx_sig.is_empty:
                raise ValueError("Solana signature should not be present.")
            if not self.sol_skd_payer.is_empty:
                raise ValueError("Solana payer should not be present.")

        if not self.is_legacy_tx:
            if self.max_priority_fee_per_gas > self.max_fee_per_gas:
                raise ValueError("max priority fee per gas higher than max fee per gas.")
            if self.chain_id is None:
                raise ValueError("chain_id should be specified")

        if self.is_scheduled_tx:
            if self.v or self.s or self.r:
                raise ValueError("Ethereum signature should not be present.")

            # TODO: remove on implement intents
            if not self.intent.is_empty:
                raise ValueError("intent should not be present.")
            if not self.intent_call_data.is_empty:
                raise ValueError("intent_call_data should not be present.")

    @classmethod
    def new_empty(
        cls,
        *,
        error: str | None = None,
        neon_tx_hash: EthTxHash = EthTxHash.default(),
    ) -> Self:
        return cls(
            tx_type=NeonTxType.DynamicGas,
            chain_id=0,  # noqa:
            neon_tx_hash=neon_tx_hash,
            from_address=EthAddress.default(),
            payer=EthAddress.default(),
            to_address=EthAddress.default(),
            contract=EthAddress.default(),
            nonce=0,
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

        try:
            if isinstance(data, NeonSkdTxModel):
                return cls._from_rlp_tx(data.rlp_tx, data.sol_skd_tx_sig, data.sol_skd_payer)
            elif isinstance(data, (str, bytes, bytearray)):
                return cls._from_rlp_tx(data)
            elif isinstance(data, EthTx):
                return cls._from_eth_tx(data, bytes())
            elif isinstance(data, dict):
                return cls._from_dict(data)
            elif isinstance(data, EthTxHash):
                return cls._from_tx_hash(data)
        except Exception as exc:
            if raise_exception:
                raise

            return cls.new_empty(error=str(exc))

        raise ValueError(f"Unsupported input type: {type(data).__name__}")

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Self:
        if "rlp_tx" in data:
            return cls._from_rlp_tx(
                data["rlp_tx"],
                data.get("sol_skd_tx_sig", None),
                data.get("sol_skd_payer", None),
            )

        return cls._from_tx_dict(data)

    @classmethod
    def _from_tx_dict(cls, data: dict[str, Any]) -> Self:
        tx_type = NeonTxType.from_raw(data.get("tx_type", NeonTxType.DynamicGas))

        exclude_list = cls._exclude_list_dict.get(tx_type)
        for value in exclude_list:
            data.pop(value, None)

        data["tx_type"] = tx_type
        data.setdefault("payer", data.get("from_address"))

        if NeonTxType.is_legacy_tx(tx_type):
            v = hex_to_uint(data.get("v", 0))
            data["chain_id"] = EthTx.calc_chain_id(v)

        return cls.from_dict(data)

    @classmethod
    def _from_rlp_tx(
        cls,
        data: str | bytes | bytearray,
        sol_skd_tx_sig: SolTxSig | None = None,
        sol_skd_payer: SolPubKey | None = None,
    ) -> Self:
        tx = EthTx.from_raw(data)
        return cls._from_eth_tx(tx, data, sol_skd_tx_sig, sol_skd_payer)

    @classmethod
    def _from_eth_tx(
        cls,
        tx: EthTx,
        rlp_tx: bytes,
        sol_skd_tx_sig: SolTxSig | None = None,
        sol_skd_payer: SolPubKey | None = None,
    ) -> Self:
        if not rlp_tx:
            rlp_tx = tx.to_bytes()

        param_dict = dict(
            tx_type=tx.tx_type,
            chain_id=tx.chain_id,
            neon_tx_hash=tx.neon_tx_hash,
            from_address=tx.from_address,
            payer=tx.payer,
            sol_skd_tx_sig=sol_skd_tx_sig or SolTxSig.default(),
            sol_skd_payer=sol_skd_payer or SolPubKey.default(),
            nonce=tx.nonce,
            index=tx.index,
            intent=tx.intent,
            intent_call_data=tx.intent_call_data,
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
        param_dict = self.to_eth_dict()
        return EthTx(**param_dict)

    @classmethod
    def _from_tx_hash(cls, neon_tx_hash: EthTxHash) -> Self:
        return cls.new_empty(neon_tx_hash=neon_tx_hash)

    @property
    def is_dynamic_gas_tx(self) -> bool:
        return NeonTxType.is_dynamic_gas_tx(self.tx_type)

    @property
    def is_legacy_tx(self) -> bool:
        return NeonTxType.is_legacy_tx(self.tx_type)

    @property
    def is_scheduled_tx(self) -> bool:
        return NeonTxType.is_scheduled_tx(self.tx_type)

    @cached_method
    def to_rlp_tx(self) -> bytes:
        return self.rlp_tx.to_bytes() if not self.rlp_tx.is_empty else self._to_eth_tx().to_bytes()

    def to_eth_dict(self) -> dict:
        param_dict = dict(
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
            param_dict["gas_price"] = self.gas_price
        elif self.is_dynamic_gas_tx:
            param_dict.update(
                dict(
                    type=self.tx_type,
                    chain_id=self.chain_id,
                    access_list=list(),
                    max_fee_per_gas=self.max_fee_per_gas,
                    max_priority_fee_per_gas=self.max_priority_fee_per_gas,
                )
            )
        elif self.is_scheduled_tx:
            raise ValueError("Not supported transaction type")
        else:
            raise ValueError("Unknown transaction type")
        return param_dict

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

    @cached_property
    def operator_fee_per_gas(self) -> int:
        return EthTx.calc_operator_fee_per_gas(self)

    @cached_property
    def effective_gas_price(self) -> int:
        return self.gas_price if self.is_legacy_tx else self.max_fee_per_gas

    @cached_property
    def cost(self) -> int:
        return self.calc_cost()

    def calc_cost(self, *, gas_limit: int | None = None, value: int | None = None) -> int:
        return EthTx.calc_cost(self, gas_limit=gas_limit, value=value)

    @cached_method
    def to_string(self) -> str:
        return str_fmt_object(self, skip_key_list=("rlp_tx",))

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


_RawNeonTxModel = Union[
    str,
    bytes,
    dict,
    NeonSkdTxModel,
    EthTxHash,
    EthTx,
    None,
]

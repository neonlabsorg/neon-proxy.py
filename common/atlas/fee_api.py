from __future__ import annotations

import logging
from typing import Annotated, Final

from pydantic import ConfigDict, Field, PlainValidator
from strenum import StrEnum

from ..solana.pubkey import SolPubKeyField
from ..utils.pydantic import BaseModel as _BaseModel, Base58Field, Base64Field

_LOG = logging.getLogger(__name__)


class BaseModel(_BaseModel):
    _model_config = _BaseModel.model_config.copy()
    _model_config.pop("extra")

    model_config = ConfigDict(
        extra="allow",
        **_model_config,
    )


class FeeTxEnc(StrEnum):
    Base64 = "Base64"
    Base58 = "Base58"


class FeeLevel(StrEnum):
    Min = "Min"
    Low = "Low"
    Medium = "Medium"
    High = "High"
    VeryHigh = "VeryHigh"
    UnsafeMax = "UnsafeMax"
    Default = "Default"
    Recommended = "Recommended"
    Unknown = "Unknown"


class FeeLevelValidator:
    _level_dict: Final[dict] = {
        v.lower(): v for v in FeeLevel
    }

    @classmethod
    def from_raw(cls, value: str | FeeLevel) -> FeeLevel:
        if isinstance(value, FeeLevel):
            return value

        try:
            value = value.lower()
            return cls._level_dict[value]
        except (BaseException,):
            _LOG.warning("")
            return FeeLevel.Unknown


FeeLevelField = Annotated[FeeLevel, PlainValidator(FeeLevelValidator.from_raw)]


class FeeCfg(BaseModel):
    tx_encoding: FeeTxEnc | None = Field(None, serialization_alias="transactionEncoding")
    level: FeeLevelField | None = Field(None, serialization_alias="priorityLevel")
    include_all_level: bool | None = Field(None, serialization_alias="includeAllPriorityFeeLevels")
    lookback_slot_cnt: int | None = Field(None, serialization_alias="lookbackSlots")
    include_vote: bool | None = Field(None, serialization_alias="includeVote")
    recommended: bool | None = Field(None)


class FeeRequest(BaseModel):
    sol_tx: Base58Field | Base64Field | None = Field(None, serialization_alias="transaction")
    account_key_list: list[SolPubKeyField] = Field(serialization_alias="accountKeys")
    cfg: FeeCfg | None = Field(None, serialization_alias="options")


class FeeResp(BaseModel):
    fee: int | float | None = Field(None, validation_alias="priorityFeeEstimate")
    fee_dict: dict[FeeLevelField, int | float] = Field(default_factory=dict, validation_alias="priorityFeeLevels")

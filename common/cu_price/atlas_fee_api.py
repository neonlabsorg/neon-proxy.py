from __future__ import annotations

import logging
from typing import Annotated

from pydantic import ConfigDict, Field, PlainValidator
from strenum import StrEnum

from ..config.config import CuPriceLevel
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


class AtlasFeeTxEnc(StrEnum):
    Base64 = "Base64"
    Base58 = "Base58"


class AtlasFeeLevelValidator:
    @classmethod
    def from_raw(cls, value: str | CuPriceLevel | None) -> CuPriceLevel:
        return CuPriceLevel.from_raw(value)


AtlasFeeLevelField = Annotated[CuPriceLevel, PlainValidator(AtlasFeeLevelValidator.from_raw)]


class AtlasFeeCfg(BaseModel):
    tx_encoding: AtlasFeeTxEnc | None = Field(None, serialization_alias="transactionEncoding")
    level: AtlasFeeLevelField | None = Field(None, serialization_alias="priorityLevel")
    include_all_level: bool | None = Field(None, serialization_alias="includeAllPriorityFeeLevels")
    lookback_slot_cnt: int | None = Field(None, serialization_alias="lookbackSlots")
    include_vote: bool | None = Field(None, serialization_alias="includeVote")
    recommended: bool | None = Field(None)


class AtlasFeeRequest(BaseModel):
    sol_tx: Base58Field | Base64Field | None = Field(None, serialization_alias="transaction")
    account_key_list: list[SolPubKeyField] = Field(serialization_alias="accountKeys")
    cfg: AtlasFeeCfg | None = Field(None, serialization_alias="options")


class AtlasFeeResp(BaseModel):
    fee: int | float | None = Field(None, validation_alias="priorityFeeEstimate")
    fee_dict: dict[AtlasFeeLevelField, int | float] = Field(default_factory=dict, validation_alias="priorityFeeLevels")

from decimal import Decimal
from typing import Annotated

from pydantic import ConfigDict, Field, PlainValidator

from ..config.config import CuPriceMode, CuPriceLevel
from ..utils.pydantic import BaseModel as _BaseModel


class BaseModel(_BaseModel):
    _model_config = _BaseModel.model_config.copy()
    _model_config.pop("extra")

    model_config = ConfigDict(
        extra="allow",
        **_model_config,
    )


CuPriceLevelField = Annotated[CuPriceLevel, PlainValidator(CuPriceLevel.from_raw)]
CuPriceModeField = Annotated[CuPriceMode, PlainValidator(CuPriceMode.from_raw)]


class PriorityFeeCfgResp(BaseModel):
    operator_fee: Decimal = Field(validation_alias="operatorFee")
    priority_fee: Decimal = Field(validation_alias="priorityFee")

    const_gas_price: int | None = Field(validation_alias="constGasPrice")
    min_gas_price: int | None = Field(validation_alias="minGasPrice")

    cu_price_mode: CuPriceModeField = Field(validation_alias="cuPriceMode")
    cu_price_level: CuPriceLevelField = Field(validation_alias="cuPriceLevel")
    def_cu_price: int = Field(validation_alias="defaultComputeUnitPrice")
    def_simple_cu_price: int = Field(validation_alias="defaultSimpleComputeUnitPrice")

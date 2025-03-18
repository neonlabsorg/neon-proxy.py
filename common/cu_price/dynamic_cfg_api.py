from decimal import Decimal
from typing import Annotated

from pydantic import ConfigDict, Field, PlainValidator

from ..config.config import CuPriceMode, CuPriceLevel
from ..utils.cached import cached_property
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
    operator_fee_value: Decimal = Field(validation_alias="operatorFee")

    priority_fee: Decimal = Field(default=Decimal(0), validation_alias="priorityFee")

    const_gas_price: int | None = Field(None, validation_alias="constGasPrice")
    min_gas_price: int | None = Field(1, validation_alias="minGasPrice")

    cu_price_mode: CuPriceModeField = Field(validation_alias="cuPriceMode")
    cu_price_level: CuPriceLevelField = Field(validation_alias="cuPriceLevel")
    cu_price_block_cnt: int | None = Field(None, validation_alias="cuPriceBlockCount")

    def_cu_price: int = Field(0, validation_alias="defaultComputeUnitPrice")
    def_simple_cu_price: int = Field(0, validation_alias="defaultSimpleComputeUnitPrice")

    @cached_property
    def operator_fee(self) -> float:
        return float(self.operator_fee_value)

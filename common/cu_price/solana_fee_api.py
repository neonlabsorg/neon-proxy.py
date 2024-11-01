from pydantic import ConfigDict, Field

from ..utils.pydantic import BaseModel as _BaseModel


class BaseModel(_BaseModel):
    _model_config = _BaseModel.model_config.copy()
    _model_config.pop("extra")

    model_config = ConfigDict(
        extra="allow",
        **_model_config,
    )


class SolPriorityFeeResp(BaseModel):
    slot: int
    cu_price: int = Field(validation_alias="prioritizationFee")

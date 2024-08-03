from __future__ import annotations

from common.utils.pydantic import BaseModel

STATISTIC_ENDPOINT = "/api/v1/statistic/"


class NeonBlockStat(BaseModel):
    start_block: int
    parsed_block: int
    finalized_block: int
    confirmed_block: int
    tracer_block: int | None


class NeonReindexBlockStat(BaseModel):
    reindex_ident: str
    start_block: int
    parsed_block: int
    stop_block: int
    term_block: int


class NeonDoneReindexStat(BaseModel):
    reindex_ident: str

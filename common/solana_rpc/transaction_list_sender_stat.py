import abc

from ..utils.pydantic import BaseModel


class SolTxDoneData(BaseModel):
    time_nsec: int


class SolTxFailData(BaseModel):
    time_nsec: int


class SolTxStatClient(abc.ABC):
    @abc.abstractmethod
    def commit_sol_tx_done(self, data: SolTxDoneData) -> None: ...

    @abc.abstractmethod
    def commit_sol_tx_fail(self, data: SolTxFailData) -> None: ...

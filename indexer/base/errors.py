class SolHistoryError(Exception):
    pass


class SolFailedHistoryError(Exception):
    def __init__(self, slot: int, message: str):
        super().__init__(slot, message)
        self._slot = slot
        self._msg = message

    @property
    def slot(self) -> int:
        return self._slot

    @property
    def message(self) -> str:
        return self._msg

    def to_string(self) -> str:
        return self._msg

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

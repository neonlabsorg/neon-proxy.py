from typing import Self, Final

import solders.instruction as _ix

from common.utils.cached import cached_property

SolAccountMeta = _ix.AccountMeta


class SolTxIx(_ix.Instruction):
    _NameAttr: Final[str] = "_name"
    _UnknownName: Final[str] = "Unknown"

    @cached_property
    def name(self) -> str:
        return getattr(self, self._NameAttr, self._UnknownName)

    @classmethod
    def clone(cls, src: _ix.Instruction, **kwargs) -> Self:
        src_kwargs = dict(
            program_id=src.program_id,
            data=src.data,
            accounts=src.accounts,
            name=getattr(src, cls._NameAttr, None),
        )
        src_kwargs.update(**kwargs)
        return cls(**src_kwargs)

    @staticmethod
    def __new__(cls, **kwargs) -> Self:
        name = kwargs.pop("name", None)
        instance = _ix.Instruction.__new__(cls, **kwargs)
        if name:
            setattr(instance, cls._NameAttr, name)
        return instance

from __future__ import annotations

import abc
from typing import Sequence, Final, Union

import solders.message as _msg
import solders.transaction as _tx

from .errors import SolTxSizeError
from .hash import SolBlockHash
from .instruction import SolAccountMeta, SolTxIx
from .pubkey import SolPubKey
from .signature import SolTxSig
from .signer import SolSigner
from ..utils.cached import reset_cached_method

SOL_PACKET_SIZE: Final[int] = 1280 - 40 - 8
_SoldersLegacyMsg = _msg.Message
_SoldersLegacyTx = _tx.Transaction

SolTxMessageInfo = Union[_msg.Message, _msg.MessageV0]


class SolTx(abc.ABC):
    def __init__(self, name: str, ix_list: Sequence[SolTxIx], *, blockhash: SolBlockHash | None = None) -> None:
        self._name = name
        self._is_signed = False
        self._is_cloned = False

        self._solders_legacy_tx: _SoldersLegacyTx
        self._build_legacy_tx(recent_blockhash=blockhash, ix_list=ix_list)

    def to_string(self) -> str:
        try:
            return self._name + ":" + self.sig.to_string()
        except (BaseException,):
            return self._name + ":<NO SIGNATURE>"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_empty(self) -> bool:
        return not self._solders_legacy_tx.message.instructions

    @property
    def is_cloned(self) -> bool:
        return self._is_cloned

    @property
    def message(self) -> SolTxMessageInfo:
        return self._solders_legacy_tx.message

    @property
    def recent_blockhash(self) -> SolBlockHash | None:
        return self._get_blockhash()

    def set_recent_blockhash(self, value: SolBlockHash | None) -> None:
        self._build_legacy_tx(recent_blockhash=value, ix_list=self._decode_ix_list())

    @property
    def account_key_list(self) -> tuple[SolPubKey, ...]:
        return self._get_account_key_list()

    @property
    def ix_list(self) -> list[SolTxIx]:
        return self._decode_ix_list()

    def add(self, *args: SolTx | SolTxIx) -> SolTx:
        ix_list = self._decode_ix_list()
        for arg in args:
            if isinstance(arg, SolTxIx):
                ix_list.append(arg)
            elif isinstance(arg, SolTx):
                ix_list.extend(arg._decode_ix_list())
            else:
                raise ValueError("invalid instruction:", arg)

        blockhash = self.recent_blockhash
        self._build_legacy_tx(recent_blockhash=blockhash, ix_list=ix_list)
        return self

    @reset_cached_method
    def serialize(self) -> bytes:
        assert self._is_signed, "transaction has not been signed"
        result = self._serialize()
        if len(result) > SOL_PACKET_SIZE:
            raise SolTxSizeError(len(result), SOL_PACKET_SIZE)
        return result

    def to_bytes(self) -> bytes:
        """Serialization which ignores signing and size"""
        return self._serialize()

    def sign(self, signer: SolSigner) -> None:
        self._sign(signer)
        self._is_signed = True
        self._reset_cache()

    def validate(self, signer: SolSigner):
        tx = self._clone()
        tx.recent_block_hash = SolBlockHash.fake()
        tx.sign(signer)
        tx.serialize()  # <- there will be exception

    def clone(self) -> SolTx:
        tx = self._clone()
        self._is_cloned = True
        return tx

    @property
    def is_signed(self) -> bool:
        return self._is_signed

    @property
    def sig(self) -> SolTxSig:
        assert self._is_signed, "Transaction has not been signed"
        return self._sig()

    # protected

    def _reset_cache(self) -> None:
        self._get_blockhash.reset_cache(self)
        self._get_account_key_list.reset_cache(self)
        self._decode_ix_list.reset_cache(self)
        self.serialize.reset_cache(self)

    @reset_cached_method
    def _get_blockhash(self) -> SolBlockHash | None:
        block_hash = self._solders_legacy_tx.message.recent_blockhash
        if block_hash == SolBlockHash.default():
            return None
        return SolBlockHash.from_raw(block_hash)

    @reset_cached_method
    def _get_account_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple([SolPubKey.from_raw(key) for key in self._solders_legacy_tx.message.account_keys])

    def _build_legacy_tx(self, recent_blockhash: SolBlockHash | None, ix_list: Sequence[SolTxIx]) -> None:
        self._is_signed = False

        if recent_blockhash is None:
            recent_blockhash = SolBlockHash.default()

        if ix_list is None:
            ix_list: list[SolTxIx] = list()

        signer: SolPubKey | None = None
        for ix in ix_list:
            for acct_meta in ix.accounts:
                if acct_meta.is_signer:
                    signer = SolPubKey.from_raw(acct_meta.pubkey)
                    break

        msg = _SoldersLegacyMsg.new_with_blockhash(ix_list, signer, recent_blockhash)
        self._solders_legacy_tx = _SoldersLegacyTx.new_unsigned(msg)
        self._reset_cache()

    @reset_cached_method
    def _decode_ix_list(self) -> list[SolTxIx]:
        msg = self._solders_legacy_tx.message
        acct_key_list = msg.account_keys
        ix_list: list[SolTxIx] = list()
        for compiled_ix in msg.instructions:
            ix_data = compiled_ix.data
            prog_id = acct_key_list[compiled_ix.program_id_index]

            acct_meta_list: list[SolAccountMeta] = list()
            for idx in compiled_ix.accounts:
                # replace signer with new one
                acct_meta = SolAccountMeta(acct_key_list[idx], msg.is_signer(idx), msg.is_writable(idx))
                acct_meta_list.append(acct_meta)

            ix_list.append(SolTxIx(prog_id, ix_data, acct_meta_list))
        return ix_list

    @abc.abstractmethod
    def _serialize(self) -> bytes:
        pass

    @abc.abstractmethod
    def _sign(self, signer: SolSigner) -> None:
        pass

    @abc.abstractmethod
    def _sig(self) -> SolTxSig:
        pass

    @abc.abstractmethod
    def _clone(self) -> SolTx:
        pass

from __future__ import annotations

from typing import Sequence

import solders.instruction as _ix
import solders.message as _msg
import solders.transaction as _tx
from typing_extensions import Self

from .alt_info import SolAltInfo
from .alt_list_filter import SolAltListFilter
from .errors import SolAltError
from .instruction import SolTxIx
from .pubkey import SolPubKey
from .signature import SolTxSig
from .signer import SolSigner
from .transaction import SolTx
from ..utils.pydantic import BaseModel, Base64Field

_SoldersMsgALT = _msg.MessageAddressTableLookup
_SoldersCompiledTxIx = _ix.CompiledInstruction
_SoldersMsgHdr = _msg.MessageHeader
_SoldersV0Msg = _msg.MessageV0
_SoldersLegacyTx = _tx.Transaction
_SoldersV0Tx = _tx.VersionedTransaction


class SolV0Tx(SolTx):
    """Versioned transaction class to represent an atomic versioned transaction."""

    class _Model(BaseModel):
        name: str
        legacy_data: Base64Field
        v0_data: Base64Field
        is_signed: bool
        is_cloned: bool
        alt_info_list: list[dict]

    def __init__(self, name: str, ix_list: Sequence[SolTxIx], alt_info_list: Sequence[SolAltInfo]) -> None:
        super().__init__(name=name, ix_list=ix_list)
        self._solders_v0_tx = _SoldersV0Tx.default()
        self._alt_info_list = list(alt_info_list)
        assert self._alt_info_list

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        model = cls._Model.from_dict(data)

        self = cls(model.name, tuple(), [SolAltInfo.from_dict(a) for a in model.alt_info_list])
        self._solders_legacy_tx = _SoldersLegacyTx.from_bytes(model.legacy_data)
        self._solders_v0_tx = _SoldersV0Tx.from_bytes(model.v0_data)
        self._is_signed = model.is_signed
        self._is_cloned = model.is_cloned
        return self

    def to_dict(self) -> dict:
        return self._Model(
            name=self._name,
            legacy_data=bytes(self._solders_legacy_tx),
            v0_data=bytes(self._solders_v0_tx),
            is_signed=self._is_signed,
            is_cloned=self._is_cloned,
            alt_info_list=[a.to_dict() for a in self._alt_info_list],
        ).to_dict()

    def _sig(self) -> SolTxSig:
        return SolTxSig.from_raw(self._solders_v0_tx.signatures[0])

    def _serialize(self) -> bytes:
        return bytes(self._solders_v0_tx)

    def _sign(self, signer: SolSigner) -> None:
        legacy_msg = self._solders_legacy_tx.message
        alt_filter = SolAltListFilter(legacy_msg, tuple())

        rw_key_set = alt_filter.rw_account_key_set
        ro_key_set = alt_filter.ro_account_key_set

        # Account indexes must index into the list of addresses
        # constructed from the concatenation of three key lists:
        #   1) message `account_keys`
        #   2) ordered list of keys loaded from `writable` lookup table indexes
        #   3) ordered list of keys loaded from `readable` lookup table indexes

        rw_key_list: list[SolPubKey] = list()
        ro_key_list: list[SolPubKey] = list()

        # Build the lookup list in the V0 transaction
        alt_msg_list: list[_SoldersMsgALT] = list()
        for alt_info in self._alt_info_list:
            rw_idx_list: list[int] = list()
            ro_idx_list: list[int] = list()
            for idx, key in enumerate(alt_info.account_key_list):
                if key in rw_key_set:
                    rw_idx_list.append(idx)
                    rw_key_list.append(key)
                    rw_key_set.discard(key)
                elif key in ro_key_set:
                    ro_idx_list.append(idx)
                    ro_key_list.append(key)
                    ro_key_set.discard(key)

            if len(rw_idx_list) == len(ro_idx_list) == 0:
                continue

            alt_msg_list.append(
                _SoldersMsgALT(
                    account_key=alt_info.address,
                    writable_indexes=bytes(rw_idx_list),
                    readonly_indexes=bytes(ro_idx_list),
                )
            )

        if not alt_msg_list:
            raise SolAltError("No account lookups to include into V0Transaction")

        # Set the positions of the static transaction accounts
        signed_key_cnt = legacy_msg.header.num_required_signatures
        tx_key_list = alt_filter.tx_account_key_list
        tx_ro_unsigned_account_key_cnt = alt_filter.tx_unsigned_account_key_cnt + len(ro_key_set)
        signed_tx_key_list, ro_tx_key_list = tx_key_list[:signed_key_cnt], tx_key_list[signed_key_cnt:]

        # This list will be included in the transaction header as defined here,
        #   so the order of accounts doesn't depend on the order in ALTs
        tx_key_list = (
            list(signed_tx_key_list)
            +
            # If the tx has an additional account key, which is not listed in the address_table_lookups
            #   then add it to the static part of the tx account list
            list(rw_key_set)
            + list(ro_key_set)
            + list(ro_tx_key_list)
        )

        key_new_idx_dict: dict[SolPubKey, int] = {
            key: idx for idx, key in enumerate(tx_key_list + rw_key_list + ro_key_list)
        }

        # Build relations between old and new indexes
        old_new_idx_dict: dict[int, int] = {}
        for old_idx, key in enumerate(alt_filter.legacy_account_key_list):
            new_idx = key_new_idx_dict.get(key, None)
            if new_idx is None:
                raise SolAltError(f"Account {key} does not exist in lookup tables")
            old_new_idx_dict[old_idx] = new_idx

        # Update compiled instructions with new indexes
        new_ix_list: list[_SoldersCompiledTxIx] = list()
        for old_ix in legacy_msg.instructions:
            # Get the new index for the program
            old_prog_idx = old_ix.program_id_index
            new_prog_idx = old_new_idx_dict.get(old_prog_idx, None)
            if new_prog_idx is None:
                raise SolAltError(f"Program with index {old_prog_idx} does not exist in account list")

            # Get new indexes for instruction accounts
            new_ix_acct_list: list[int] = list()
            for old_idx in old_ix.accounts:
                new_idx = old_new_idx_dict.get(old_idx, None)
                if new_idx is None:
                    raise SolAltError(f"Account with index {old_idx} does not exist in account list")
                new_ix_acct_list.append(new_idx)

            new_ix_list.append(
                _SoldersCompiledTxIx(
                    program_id_index=new_prog_idx,
                    data=old_ix.data,
                    accounts=bytes(new_ix_acct_list),
                )
            )

        hdr = _SoldersMsgHdr(
            num_required_signatures=legacy_msg.header.num_required_signatures,
            num_readonly_signed_accounts=legacy_msg.header.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts=tx_ro_unsigned_account_key_cnt,
        )

        msg = _SoldersV0Msg(
            header=hdr,
            account_keys=tuple(tx_key_list),
            recent_blockhash=legacy_msg.recent_blockhash,
            instructions=tuple(new_ix_list),
            address_table_lookups=tuple(alt_msg_list),
        )

        self._solders_v0_tx = _SoldersV0Tx(msg, (signer.keypair,))

    def _clone(self) -> SolV0Tx:
        return SolV0Tx(self._name, self._decode_ix_list(), self._alt_info_list)

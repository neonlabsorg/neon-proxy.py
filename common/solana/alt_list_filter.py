from .alt_program import SolAltProg
from .errors import SolAltError
from .pubkey import SolPubKey
from .transaction_legacy import SolLegacyMsg
from ..utils.cached import cached_property


class SolAltListFilter:
    def __init__(self, legacy_msg: SolLegacyMsg) -> None:
        self._msg = legacy_msg
        self._validate_legacy_msg()

    @cached_property
    def legacy_account_key_list(self) -> tuple[SolPubKey, ...]:
        return tuple([SolPubKey.from_raw(key) for key in self._msg.account_keys])

    @property
    def tx_unsigned_account_key_cnt(self) -> int:
        return len(self._prog_id_set)

    @cached_property
    def tx_account_key_list(self) -> tuple[SolPubKey, ...]:
        # Returns the list in the order from the tx, because keys is are already ordered in the tx
        return tuple([key for key in self.legacy_account_key_list if key in self._tx_acct_key_set])

    @cached_property
    def ro_account_key_set(self) -> set[SolPubKey]:
        ro_acct_key_set = set(self.legacy_account_key_list[self._start_ro_key_idx :])
        return ro_acct_key_set.difference(self._tx_acct_key_set)

    @cached_property
    def rw_account_key_set(self) -> set[SolPubKey]:
        start_ro_idx = self._start_ro_key_idx
        rw_acct_key_set = set(self.legacy_account_key_list[self._msg.header.num_required_signatures : start_ro_idx])
        return rw_acct_key_set.difference(self._tx_acct_key_set)

    @cached_property
    def alt_account_key_set(self) -> set[SolPubKey]:
        # All other accounts can be included into a lookup table
        alt_acct_key_set = set(self.legacy_account_key_list[self._msg.header.num_required_signatures :])
        alt_acct_key_set.difference_update(self._tx_acct_key_set)

        if len(alt_acct_key_set) + len(self._tx_acct_key_set) != len(self._msg.account_keys):
            raise SolAltError("Found duplicates in the transaction account list")

        return alt_acct_key_set

    # protected:
    @cached_property
    def _tx_acct_key_set(self) -> set[SolPubKey]:
        # required accounts should be included into the transaction
        required_key_set = set(self.legacy_account_key_list[: self._msg.header.num_required_signatures])

        # programs should be included into the transaction
        # the result set of accounts in the static part of a transaction
        tx_acct_key_set = required_key_set.union(self._prog_id_set)
        if not tx_acct_key_set:
            raise SolAltError("Zero number of static transaction accounts")
        elif len(tx_acct_key_set) != len(required_key_set) + len(self._prog_id_set):
            raise SolAltError("Transaction uses signature from a program?")
        elif len(tx_acct_key_set) > SolAltProg.MaxTxAccountCnt:
            raise SolAltError(
                f"Too big number of transactions account keys: {len(tx_acct_key_set)} > {SolAltProg.MaxTxAccountCnt}"
            )

        return tx_acct_key_set

    @cached_property
    def _prog_id_set(self) -> set[SolPubKey]:
        return set([SolPubKey.from_raw(key) for key in self._msg.program_ids()])

    def _validate_legacy_msg(self) -> None:
        req_sig_cnt = self._msg.header.num_required_signatures
        if req_sig_cnt > SolAltProg.MaxRequiredSigCnt:
            raise SolAltError(f"Too big number {req_sig_cnt} of signed accounts for a V0Transaction")
        elif len(self._msg.account_keys) > SolAltProg.MaxAltAccountCnt:
            raise SolAltError(f"Too big number {len(self._msg.account_keys)} of accounts for a V0Transaction")
        else:
            # additional checks happen inside the functions
            _ = self._tx_acct_key_set
            _ = self.alt_account_key_set

    @cached_property
    def _start_ro_key_idx(self) -> int:
        key_list_len = len(self.legacy_account_key_list)
        return key_list_len - self._msg.header.num_readonly_unsigned_accounts

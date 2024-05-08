from typing import Final

import solders.system_program as _sys

from .instruction import SolTxIx
from .pubkey import SolPubKey


class SolSysProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_sys.ID)

    @classmethod
    def make_create_account_with_seed_ix(
        cls,
        *,
        address: SolPubKey,
        owner: SolPubKey,
        payer: SolPubKey,
        seed: str,
        balance: int,
        size: int,
    ) -> SolTxIx:
        return _sys.create_account_with_seed(
            _sys.CreateAccountWithSeedParams(
                from_pubkey=payer,
                to_pubkey=address,
                base=payer,
                seed=seed,
                lamports=balance,
                space=size,
                owner=owner,
            )
        )

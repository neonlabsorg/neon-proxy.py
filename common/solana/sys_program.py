from typing import Final

import solders.system_program as _sys
import solders.sysvar as _var

from .instruction import SolTxIx
from .pubkey import SolPubKey


class SolSysProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_sys.ID)
    ClockVar: Final[SolPubKey] = SolPubKey.from_raw(_var.CLOCK)
    RecentBlockHashVar: Final[SolPubKey] = SolPubKey.from_raw(_var.RECENT_BLOCKHASHES)
    RentVar: Final[SolPubKey] = SolPubKey.from_raw(_var.RENT)
    RewardVar: Final[SolPubKey] = SolPubKey.from_raw(_var.REWARDS)
    StakeHistoryVar: Final[SolPubKey] = SolPubKey.from_raw(_var.STAKE_HISTORY)
    EpochScheduleVar: Final[SolPubKey] = SolPubKey.from_raw(_var.EPOCH_SCHEDULE)
    IxListVar: Final[SolPubKey] = SolPubKey.from_raw(_var.INSTRUCTIONS)
    SlotHashVar: Final[SolPubKey] = SolPubKey.from_raw(_var.SLOT_HASHES)
    VoteProgram: Final[SolPubKey] = SolPubKey.from_string("Vote111111111111111111111111111111111111111")

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

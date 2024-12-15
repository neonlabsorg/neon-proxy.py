from typing import Final

from .pubkey import SolPubKey


class SolVoteProg:
    ID: Final[SolPubKey] = SolPubKey.from_string("Vote111111111111111111111111111111111111111")

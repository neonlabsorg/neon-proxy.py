from typing import Final

import solders.token as _token

from .pubkey import SolPubKey


class SplTokenProg:
    ID: Final[SolPubKey] = SolPubKey.from_raw(_token.ID)

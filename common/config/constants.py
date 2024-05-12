import os
from typing import Final

from ..solana.pubkey import SolPubKey
from ..solana.transaction import SOL_PACKET_SIZE as _SOL_PKT_SIZE

ONE_BLOCK_SEC: Final[float] = float(os.environ.get("SOLANA_BLOCK_SEC", "0.4"))
MIN_FINALIZE_SEC: Final[float] = ONE_BLOCK_SEC * 32
SOL_PACKET_SIZE: Final[int] = _SOL_PKT_SIZE
NEON_EVM_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw(
    os.environ.get("NEON_EVM_PROGRAM", os.environ.get("EVM_LOADER"))  # EVM_LOADER for compatibility only
)
DEFAULT_TOKEN_NAME: Final[str] = os.environ.get("DEFAULT_TOKEN_NAME", "neon").strip().upper()
CHAIN_TOKEN_NAME: Final[str] = os.environ.get("CHAIN_TOKEN_NAME", "sol").strip().upper()

NEON_PROXY_MAJOR_VER = 1
NEON_PROXY_MINOR_VER = 11
NEON_PROXY_BUILD_VER = 100
_REVISION = "NEON_PROXY_REVISION_TO_BE_REPLACED"
NEON_PROXY_PKG_VER = f"Neon-Proxy/v{NEON_PROXY_MAJOR_VER}.{NEON_PROXY_MINOR_VER}.{NEON_PROXY_BUILD_VER}-dev-{_REVISION}"

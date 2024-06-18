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

MAINNET_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw("NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG")
MAINNET_GENESIS_HASH: Final[str] = "7f1vrAJpnAFdqwNZQe8Z4pEnJjGDMeQqPWQ9Xf198byy"  # 195'350'522
MAINNET_GENESIS_TIME: Final[int] = 1684768103

DEVNET_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw("eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")
DEVNET_GENESIS_HASH: Final[str] = "4GoSwc9RDGduTDCLUgrHSEdMA5iMcigMfXkLEozNB8pX"   # 120'292'196
DEVNET_GENESIS_TIME: Final[int] = 1647021674

UNKNOWN_GENESIS_HASH: Final[str] = "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWcmM"  # Fake 0xFFFF..0000

_MAJOR_VER = 1
_MINOR_VER = 14
_BUILD_VER = 7
_REVISION = "NEON_PROXY_REVISION_TO_BE_REPLACED"
NEON_PROXY_VER = f"v{_MAJOR_VER}.{_MINOR_VER}.{_BUILD_VER}-{_REVISION}"

NEON_PROXY_PKG_VER = f"Neon-Proxy/{NEON_PROXY_VER}"

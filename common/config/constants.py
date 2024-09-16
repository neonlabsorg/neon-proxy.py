import os
from typing import Final

from ..solana.pubkey import SolPubKey

######################################
# Solana general settings:
ONE_BLOCK_SEC: Final[float] = float(os.environ.get("SOLANA_BLOCK_SEC", "0.4"))
MIN_FINALIZE_SEC: Final[float] = ONE_BLOCK_SEC * 32
SOL_PKT_SIZE: Final[int] = 1280 - 40 - 8

######################################
# Solana CB settings:
_DEF_SOLANA_MAX_HEAP_SIZE: Final[int] = 256 * 1024
SOLANA_MAX_HEAP_SIZE: Final[int] = int(os.environ.get("SOLANA_MAX_HEAP_SIZE", str(_DEF_SOLANA_MAX_HEAP_SIZE)))

_DEF_SOLANA_MAX_CU_LIMIT: Final[int] = 1_400_000
SOLANA_MAX_CU_LIMIT: Final[int] = int(os.environ.get("SOLANA_MAX_CU_LIMIT", str(_DEF_SOLANA_MAX_CU_LIMIT)))

_DEF_SOLANA_DEFAULT_CU_LIMIT: Final[int] = 200_000
SOLANA_DEFAULT_CU_LIMIT: Final[int] = int(os.environ.get("SOLANA_DEFAULT_CU_LIMIT", str(_DEF_SOLANA_DEFAULT_CU_LIMIT)))

######################################
# Neon settings:
NEON_EVM_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw(
    os.environ.get("NEON_EVM_PROGRAM", os.environ.get("EVM_LOADER"))  # EVM_LOADER for compatibility only
)
DEFAULT_TOKEN_NAME: Final[str] = os.environ.get("DEFAULT_TOKEN_NAME", "neon").strip().upper()
CHAIN_TOKEN_NAME: Final[str] = os.environ.get("CHAIN_TOKEN_NAME", "sol").strip().upper()

MAINNET_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw("NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG")
MAINNET_GENESIS_HASH: Final[str] = "7f1vrAJpnAFdqwNZQe8Z4pEnJjGDMeQqPWQ9Xf198byy"  # 195'350'522
MAINNET_GENESIS_TIME: Final[int] = 1684768103

DEVNET_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw("eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")
DEVNET_GENESIS_HASH: Final[str] = "4GoSwc9RDGduTDCLUgrHSEdMA5iMcigMfXkLEozNB8pX"  # 120'292'196
DEVNET_GENESIS_TIME: Final[int] = 1647021674

ROLLUP_PROGRAM_ID: Final[SolPubKey] = SolPubKey.from_raw("EgbRZxFRQTiZpQGinE5jT6KQq5jtVnjtLdSTkW5UTcAv")
# TODO: specify real block number when evm was deployed on the rollup.
ROLLUP_GENESIS_HASH: Final[str] = os.environ.get("ROLLUP_GENESIS_HASH", "UNSPECIFIED_ROLLUP_GENESIS_HASH")
# TODO: specify genesis timestamp once deployed.
ROLLUP_GENESIS_TIME: Final[int] = int(os.environ.get("ROLLUP_GENESIS_TIME", "0"))

UNKNOWN_GENESIS_HASH: Final[str] = "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWcmM"  # Fake 0xFFFF..0000

_MAJOR_VER = 1
_MINOR_VER = 15
_BUILD_VER = 1
_REVISION = "NEON_PROXY_REVISION_TO_BE_REPLACED"
NEON_PROXY_VER = f"v{_MAJOR_VER}.{_MINOR_VER}.{_BUILD_VER}-{_REVISION}"

NEON_PROXY_PKG_VER = f"Neon-Proxy/{NEON_PROXY_VER}"


# Sanity check - make sure that CB settings are defaults if PROGRAM_ID is not rollup (so it's not changed by mistake).
def _validate() -> None:
    if NEON_EVM_PROGRAM_ID == ROLLUP_PROGRAM_ID:
        return
    # If not rollup, solana mainnet defaults should be used.
    if (
        SOLANA_MAX_HEAP_SIZE != _DEF_SOLANA_MAX_HEAP_SIZE
        or SOLANA_MAX_CU_LIMIT != _DEF_SOLANA_MAX_CU_LIMIT
        or SOLANA_DEFAULT_CU_LIMIT != _DEF_SOLANA_DEFAULT_CU_LIMIT
    ):
        raise ValueError("Incorrect CB settings. Default CB Solana settings should be used for anything but rollup.")


_validate()

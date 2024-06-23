import math
from collections import deque
from dataclasses import dataclass

from eth_hash.auto import keccak
from typing_extensions import Self

from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.neon.neon_program import NeonProg
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner


@dataclass(frozen=True)
class OpHolderInfo:
    resource_id: int
    seed: str
    address: SolPubKey

    @classmethod
    def from_raw(cls, owner: SolPubKey, resource_id: int) -> Self:
        holder_seed = cls._perm_account_seed(b"holder-", resource_id)
        addr = cls._neon_account_with_seed(owner, holder_seed)
        return cls(resource_id=resource_id, seed=holder_seed, address=addr)

    @staticmethod
    def _perm_account_seed(prefix: bytes, resource_id: int) -> str:
        aid = resource_id.to_bytes(math.ceil(resource_id.bit_length() / 8), "big")
        seed_base = prefix + aid
        return keccak(seed_base).hex()[:32]

    @staticmethod
    def _neon_account_with_seed(base_address: SolPubKey, seed: str) -> SolPubKey:
        return SolPubKey.create_with_seed(base_address, seed, NeonProg.ID)


@dataclass
class OpSignerInfo:
    signer: SolSigner
    neon_account: NeonAccount
    token_sol_address_dict: dict[int, SolPubKey]

    free_holder_list: deque[OpHolderInfo]
    used_holder_dict: dict[SolPubKey, OpHolderInfo]
    disabled_holder_list: deque[OpHolderInfo]

    error_cnt: int = 0
    warn_cnt: int = 0

    @property
    def owner(self) -> SolPubKey:
        return self.signer.pubkey

    @property
    def eth_address(self) -> EthAddress:
        return self.neon_account.eth_address

    def pop_free_holder_list(self) -> deque[OpHolderInfo]:
        holder_list, self.free_holder_list = self.free_holder_list, deque()
        return holder_list

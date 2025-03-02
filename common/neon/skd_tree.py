from typing_extensions import Self

from .address import NeonAddress
from .neon_program import NeonProg
from ..ethereum.hash import EthAddress
from ..solana.pubkey import SolPubKey
from ..utils.cached import cached_property, cached_method


class NeonSkdTreeAddress:
    def __init__(
        self,
        address: NeonAddress,
        nonce: int
    ) -> None:
        self._address = address
        self._nonce = nonce

    @classmethod
    def from_raw(cls, data: NeonAddress, nonce: int) -> Self:
        assert isinstance(data, NeonAddress)
        return cls(data, nonce)

    @cached_property
    def address(self) -> SolPubKey:
        seed_list = [
            NeonProg.AccountSeedVersion.to_bytes(1, "little"),
            b"TREE",
            self._address.eth_address.to_bytes(),
            self._address.chain_id.to_bytes(8, "little"),
            self._nonce.to_bytes(8, "little"),
        ]
        addr, _ = SolPubKey.find_program_address(seed_list, NeonProg.ID)

        return addr

    @property
    def neon_address(self) -> NeonAddress:
        return self._address

    @property
    def eth_address(self) -> EthAddress:
        return self._address.eth_address

    @property
    def chain_id(self) -> int:
        return self._address.chain_id

    @property
    def nonce(self) -> int:
        return self._nonce

    def to_string(self) -> str:
        return self.address.to_string()

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

    @cached_method
    def __hash__(self) -> int:
        return self.address.__hash__()

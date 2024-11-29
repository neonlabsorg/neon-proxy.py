from common.ethereum.hash import EthTxHash
from common.neon_rpc.api import HolderAccountModel
from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_method


class WrongStrategyError(Exception):
    def __str__(self) -> str:
        return "Wrong strategy"


class BadResourceError(Exception):
    def __str__(self) -> str:
        return "Bad resource"


class StuckTxError(Exception):
    def __init__(self, holder: HolderAccountModel) -> None:
        super().__init__()
        self._neon_tx_hash = holder.neon_tx_hash
        self._chain_id = holder.chain_id
        self._holder_address = holder.address

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self._neon_tx_hash

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def holder_address(self) -> SolPubKey:
        return self._holder_address

    @cached_method
    def to_string(self) -> str:
        return f"Holder {self._holder_address} contains stuck tx {self._neon_tx_hash}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class SkdTxError(Exception):
    def __init__(self, neon_tx_hash: EthTxHash) -> None:
        super().__init__()
        self._neon_tx_hash = neon_tx_hash

    @cached_method
    def to_string(self) -> str:
        return f"NeonSkdTx {self._neon_tx_hash} is already finished"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()

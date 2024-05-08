from common.ethereum.hash import EthTxHash
from common.solana.pubkey import SolPubKey
from common.utils.cached import cached_method


class WrongStrategyError(Exception):
    pass


class BadResourceError(Exception):
    pass


class StuckTxError(Exception):
    def __init__(self, neon_tx_hash: EthTxHash, chain_id: int, address: SolPubKey) -> None:
        super().__init__()
        self._neon_tx_hash = neon_tx_hash
        self._chain_id = chain_id
        self._address = address

    @property
    def neon_tx_hash(self) -> EthTxHash:
        return self._neon_tx_hash

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def address(self) -> SolPubKey:
        return self._address

    @cached_method
    def to_string(self) -> str:
        return f"Holder {self._neon_tx_hash} contains stuck tx {self._neon_tx_hash}:{hex(self._chain_id)}"

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return self.to_string()


class TxAccountCntTooHighError(Exception):
    def __init__(self, current_cnt: int, limit_cnt: int) -> None:
        msg = f"The transaction requests {current_cnt} accounts and exceeds the upper limit of {limit_cnt}"
        super().__init__(msg)

        self._current_cnt = current_cnt
        self._limit_cnt = limit_cnt

    @property
    def current_amount(self) -> int:
        return self._current_cnt

    @property
    def limit_amount(self) -> int:
        return self._limit_cnt

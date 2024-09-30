import logging

from common.ethereum.hash import EthTxHash
from common.neon_rpc.api import HolderAccountModel, HolderAccountStatus
from common.neon_rpc.client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.utils.cached import ttl_cached_method

_LOG = logging.getLogger(__name__)


class HolderAccountValidator:
    def __init__(self, core_api_client: CoreApiClient, holder_address: SolPubKey, neon_tx_hash: EthTxHash) -> None:
        self._core_api_client = core_api_client
        self._holder_address = holder_address
        self._neon_tx_hash = neon_tx_hash
        self._holder_acct: HolderAccountModel | None = None

    @ttl_cached_method(ttl_msec=50)
    async def refresh(self) -> HolderAccountModel:
        self._holder_acct = await self._core_api_client.get_holder_account(self._holder_address)

        _LOG.debug(
            "holder %s contains NeonTx %s with block_params %s, status %s and %d completed EVM steps",
            self._holder_address,
            self._holder_acct.neon_tx_hash,
            self._holder_acct.block_params,
            self._holder_acct.status,
            self._holder_acct.evm_step_cnt,
        )

        return self._holder_acct

    @property
    def holder_account(self) -> HolderAccountModel:
        assert self._holder_acct
        return self._holder_acct

    @property
    def is_valid(self) -> bool:
        return self._holder_acct.neon_tx_hash == self._neon_tx_hash

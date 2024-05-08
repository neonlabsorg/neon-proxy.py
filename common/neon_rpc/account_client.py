import abc

from .api import NeonAccountModel, HolderAccountModel
from ..neon.account import NeonAccount
from ..solana.pubkey import SolPubKey


class CoreApiAccountClient(abc.ABC):
    @abc.abstractmethod
    async def get_neon_account_model(self, neon_account: NeonAccount) -> NeonAccountModel: ...

    @abc.abstractmethod
    async def get_holder_account_model(self, neon_account: SolPubKey) -> HolderAccountModel: ...

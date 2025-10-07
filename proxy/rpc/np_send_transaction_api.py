import logging
from typing import ClassVar

from common.ethereum.bin_str import EthBinStrField
from common.ethereum.errors import EthError, EthWrongChainIdError
from common.ethereum.hash import EthTxHashField
from common.http.utils import HttpRequestCtx
from common.neon.address import NeonAddress
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .server_abc import NeonProxyApi
from ..base.rpc_transaction_executor import RpcNeonTxExecutor

_LOG = logging.getLogger(__name__)


class NpExecTxApi(NeonProxyApi):
    name: ClassVar[str] = "NeonRPC::ExecuteTransaction"

    @cached_property
    def _tx_executor(self) -> RpcNeonTxExecutor:
        return RpcNeonTxExecutor(self._server)

    @NeonProxyApi.method(name="eth_sendRawTransaction")
    async def send_raw_tx(self, ctx: HttpRequestCtx, raw_tx: EthBinStrField) -> EthTxHashField:
        return await self._tx_executor.send_neon_tx(ctx, raw_tx.to_bytes())

    @NeonProxyApi.method(name="neon_sendRawScheduledTransaction")
    async def send_skd_raw_tx(self, ctx: HttpRequestCtx, raw_tx: EthBinStrField) -> EthTxHashField:
        self._validate_layer0_chain_id(ctx)

        neon_tx = self._tx_executor.parse_neon_tx(raw_tx.to_bytes())
        tx_id = neon_tx.neon_tx_hash.ident
        with logging_context(tx=tx_id):
            _LOG.debug("sendRawSkdTransaction %s", neon_tx.neon_tx_hash)

            if not neon_tx.is_scheduled_tx:
                raise EthError("not-scheduled transaction")
            elif neon_tx.chain_id != self._get_chain_id(ctx):
                _LOG.debug("WRONG chain_id %s", neon_tx.chain_id)
                raise EthWrongChainIdError()

            payer = NeonAddress.from_raw(neon_tx.payer, neon_tx.chain_id)
            tree = await self._core_api_client.get_neon_skd_tree(payer, neon_tx.nonce, None)

            if neon_tx.index >= len(tree.node_list):
                raise EthError("unknown transaction hash")

            node = tree.node_list[neon_tx.index]
            node_info = (node.neon_tx_hash, tree.max_fee_per_gas, tree.max_priority_fee_per_gas)
            tx_info = (neon_tx.neon_tx_hash, neon_tx.max_fee_per_gas, neon_tx.max_priority_fee_per_gas)
            if node_info != tx_info:
                raise EthError("unknown transaction hash")

            neon_skd_tx = await self._db.get_neon_skd_tx_by_hash(neon_tx.neon_tx_hash)
            if neon_skd_tx and neon_skd_tx.rlp_tx:
                return neon_tx.neon_tx_hash

            # keep information about Solana scheduled Tx
            if neon_skd_tx and (not neon_skd_tx.sol_skd_tx_sig.is_empty):
                skd_info = dict(sol_skd_tx_sig=neon_skd_tx.sol_skd_tx_sig, sol_skd_payer=neon_skd_tx.sol_skd_payer)
            elif root_skd_tx := await self._db.get_neon_skd_tx_by_hash(tree.root_neon_tx_hash):
                skd_info = dict(sol_skd_tx_sig=root_skd_tx.sol_skd_tx_sig, sol_skd_payer=root_skd_tx.sol_skd_payer)
            else:
                skd_info = dict()

            if skd_info:
                neon_tx = neon_tx.model_copy(update=skd_info)

            await self._db.commit_neon_skd_tx(tree.last_slot, tree.address, tree.root_neon_tx_hash, neon_tx)
            return neon_tx.neon_tx_hash

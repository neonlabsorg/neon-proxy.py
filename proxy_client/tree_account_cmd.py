import json
import logging
from typing import ClassVar, Final, Sequence, Self

from common.config.config import Config
from common.ethereum.hash import EthAddress
from common.neon.address import NeonAddress
from common.neon.neon_program import NeonProg, NeonEvmIxCode, NeonBaseTxAccountSet
from common.neon.skd_tree import NeonSkdTreeAddress
from common.neon_rpc.api import NeonSkdTreeModel
from common.neon_rpc.client import CoreApiClient
from common.solana.cb_program import SolCbProg
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.transaction_legacy import SolLegacyTx
from common.utils.json_logger import logging_context
from proxy.base.op_client import OpResourceClient
from .cmd_handler import BaseNPCmdHandler

_LOG = logging.getLogger(__name__)


class TreeAccountHandler(BaseNPCmdHandler):
    command: ClassVar[str] = "tree-account"
    #
    # protected:
    _info: Final[str] = "info"
    _destroy: Final[str] = "destroy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(self.command, description="Commands on Tree Accounts")
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        def _add_tree_opt(_parser) -> None:
            _parser.add_argument(
                "sender",
                type=str,
                nargs="?",
                help="Address of the sender",
            )
            _parser.add_argument(
                "chain_id",
                type=int,
                nargs="?",
                help="ChainId of the sender",
            )
            _parser.add_argument(
                "nonce",
                type=int,
                nargs="?",
                help="Nonce of the Scheduled transaction",
            )

        self._info_parser = self._cmd_parser.add_parser(cls._info, help="info for tree-account")
        self._subcmd_dict[cls._info] = self._info_cmd
        _add_tree_opt(self._info_parser)

        self._destroy_parser = self._cmd_parser.add_parser(cls._destroy, help="destroy tree-account")
        self._subcmd_dict[cls._destroy] = self._destroy_cmd
        _add_tree_opt(self._destroy_parser)
        self._destroy_parser.add_argument(
            "timeout",
            type=int,
            default=3,
            nargs="?",
            help="timeout in seconds to wait the result from Solana",
        )

        return self

    async def _info_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            skd_tree_addr, skd_tree_acct = await self._get_tree_acct(arg_space)

            obj = dict(
                address=skd_tree_addr.address.to_string(),
                status=skd_tree_acct.status.value,
                activeStatus=skd_tree_acct.active_status.name,
                payer=skd_tree_addr.eth_address.to_string(),
                chainId=skd_tree_addr.chain_id,
                nonce=skd_tree_addr.nonce,
                lastSlot=skd_tree_acct.last_slot,
                maxFeePerGas=skd_tree_acct.max_fee_per_gas,
                maxPriorityFeePerGas=skd_tree_acct.max_priority_fee_per_gas,
                balance=skd_tree_acct.balance / pow(10, 18),
                lastIndex=skd_tree_acct.last_idx,
                transactions=[
                    dict(
                        status=n.status.name,
                        resultHash=n.result_hash.to_string(),
                        transactionHash=n.neon_tx_hash.to_string(),
                        gasLimit=n.gas_limit,
                        value=n.value,
                        childTransactionIndex=n.child_tx_idx,
                        successExecutionLimit=n.success_exec_limit,
                        parentCount=n.parent_cnt,
                    ) for n in skd_tree_acct.node_list
                ]
            )
            print(json.dumps(obj, indent=2))

        return 0

    async def _destroy_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            skd_tree_addr, skd_tree_acct = await self._get_tree_acct(arg_space)
            if not skd_tree_acct.is_exist:
                _LOG.warning("tree account %s does not exist", skd_tree_addr)
                return 1

            op_client: OpResourceClient = await self._get_op_client()
            if (op_res := await op_client.get_resource(req_id, skd_tree_addr.chain_id)).is_empty:
                _LOG.error("no available resource to process the Tree Account destroying")
                return 1

            core_api_client: CoreApiClient = await self._get_core_api_client()
            payer_acct = await core_api_client.get_neon_account(skd_tree_addr.neon_address, None)
            tx_sol_addr = NeonBaseTxAccountSet(
                raw_payer=payer_acct.sol_address,
                raw_payer_container=payer_acct.container_address,
                raw_sender=SolPubKey.default(),
                raw_sender_container=SolPubKey.default(),
                raw_receiver=SolPubKey.default(),
                raw_receiver_container=SolPubKey.default(),
                receiver_contract=SolPubKey.default(),
                payer_balance=0,
            )

            neon_prog = NeonProg(op_res.owner)
            # fmt: off
            neon_prog.init_skd_tree_address(
                skd_tree_addr.address
            ).init_neon_tx(
                skd_tree_acct.node_list[0].neon_tx_hash, bytes()
            ).init_tx_sol_address(
                tx_sol_addr
            )
            # fmt: on

            destroy_ix = neon_prog.make_destroy_skd_tree_ix()

            cu_price_ix = SolCbProg.make_cu_price_ix(self._cfg.def_simple_cu_price)
            cu_limit_ix = SolCbProg.make_cu_limit_ix(neon_prog.CuLimitSkdTreeAccountDestroy)
            ix_list: Sequence[SolTxIx] = tuple([cu_price_ix, cu_limit_ix, destroy_ix])

            destroy_tx = SolLegacyTx(NeonEvmIxCode.SkdTreeDestroy.name, ix_list=ix_list)
            await self._send_tx_list(req_id, op_res.owner, tuple([destroy_tx]), arg_space.timeout)

        return 0

    async def _get_tree_acct(self, arg_space) -> tuple[NeonSkdTreeAddress, NeonSkdTreeModel]:
        try:
            sender = SolPubKey.from_raw(arg_space.sender)
        except (BaseException,):
            sender = EthAddress.from_raw(arg_space.sender)

        core_api_client: CoreApiClient = await self._get_core_api_client()

        sender_addr = NeonAddress.from_raw(sender, arg_space.chain_id)
        skd_tree_addr = NeonSkdTreeAddress.from_raw(sender_addr, arg_space.nonce)
        print("Tree account: ", skd_tree_addr)

        skd_tree_acct = await core_api_client.get_neon_skd_tree(sender_addr, arg_space.nonce, None)
        return skd_tree_addr, skd_tree_acct

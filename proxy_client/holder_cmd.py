import asyncio
import logging
from typing import Final, Sequence

from typing_extensions import Self

from common.config.config import Config
from common.neon.neon_program import NeonProg, NeonEvmIxCode
from common.neon_rpc.api import HolderAccountStatus, HolderAccountModel
from common.neon_rpc.client import CoreApiClient
from common.solana.alt_info import SolAltInfo
from common.solana.cb_program import SolCbProg
from common.solana.commit_level import SolCommit
from common.solana.instruction import SolAccountMeta
from common.solana.pubkey import SolPubKey
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_v0 import SolV0Tx
from common.solana_rpc.alt_builder import SolAltTxBuilder
from common.solana_rpc.client import SolClient
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from proxy.base.op_api import OpResourceModel
from proxy.base.op_client import OpResourceClient
from proxy.operator_resource.key_info import OpHolderInfo
from .cmd_handler import BaseNPCmdHandler

_LOG = logging.getLogger(__name__)


class HolderHandler(BaseNPCmdHandler):
    command = "holder"
    #
    # protected:
    _cancel: Final[str] = "cancel"
    _list: Final[str] = "list"
    _destroy: Final[str] = "destroy"

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(self.command)
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._cancel_parser = self._cmd_parser.add_parser(cls._cancel, help="cancel a Neon transaction in a Holder")
        self._subcmd_dict[cls._cancel] = self._cancel_cmd
        self._cancel_parser.add_argument(
            "holder",
            type=str,
            nargs="?",
            help="address of the holder",
        )
        self._cancel_parser.add_argument(
            "timeout",
            type=int,
            default=3,
            nargs="?",
            help="timeout in seconds to wait the result from Solana",
        )

        self._list_parser = self._cmd_parser.add_parser(cls._list, help="list Holders")
        self._subcmd_dict[cls._list] = self._list_cmd
        self._list_parser.add_argument(
            "start",
            type=int,
            nargs="?",
            default=self._cfg.perm_account_id,
            help="start identifier for Holder",
        )
        self._list_parser.add_argument(
            "number",
            type=int,
            nargs="?",
            default=self._cfg.perm_account_limit,
            help="number of Holders to list",
        )
        self._list_parser.add_argument(
            "seed",
            type=str,
            nargs="?",
            default=OpHolderInfo.default_prefix.decode("utf-8"),
            help="seed prefix for the Holder PDA",
        )

        self._destroy_parser = self._cmd_parser.add_parser(cls._destroy, help="destroy a Holder")
        self._subcmd_dict[self._destroy] = self._destroy_cmd
        self._destroy_parser.add_argument(
            "holder",
            type=str,
            nargs="?",
            help="address of the Holder",
        )

        return self

    async def _cancel_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            holder_addr = SolPubKey.from_raw(arg_space.holder)
            timeout_sec = arg_space.timeout

            core_api_client = await self._get_core_api_client()
            holder = await core_api_client.get_holder_account(holder_addr)
            if holder.status != HolderAccountStatus.Active:
                _LOG.error("holder %s doesn't have an active NeonTx", holder_addr)
                return 1
            _LOG.info("holder %s has the active NeonTx %s", holder_addr, holder.neon_tx_hash)

            op_client: OpResourceClient = await self._get_op_client()
            if (op_res := await op_client.get_resource(req_id, holder.chain_id)).is_empty:
                _LOG.error("no available resource to process the NeonTx canceling")
                return 1

            try:
                if not (await self._cancel_cmd_impl(req_id, holder, op_res, timeout_sec)):
                    return 1

                holder = await core_api_client.get_holder_account(holder_addr)
                if holder.status == HolderAccountStatus.Active:
                    _LOG.info("holder %s has the active NeonTx %s", holder_addr, holder.neon_tx_hash)
                    return 1

                return 0
            finally:
                await op_client.free_resource(req_id, True, op_res)

    async def _list_cmd(self, arg_space) -> int:
        assert arg_space.number > 0
        assert arg_space.start >= 0

        start_id = arg_space.start
        stop_id = start_id + arg_space.number
        seed = arg_space.seed.encode("utf-8")

        op_client: OpResourceClient = await self._get_op_client()
        core_api_client: CoreApiClient = await self._get_core_api_client()
        sol_client: SolClient = await self._get_sol_client()

        size_balance_dict: dict[int, int] = dict()

        async def _balance(size: int) -> int:
            if not size:
                return 0

            if value := size_balance_dict.get(size, 0):
                return value

            value = await sol_client.get_rent_balance_for_size(size)
            size_balance_dict[size] = value
            return value

        total_balance = 0
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            key_list = await op_client.get_signer_key_list(req_id)

            for key in key_list:
                key_total_balance = 0
                print("{}:".format(key))

                for res_id in range(start_id, stop_id):
                    op_info = OpHolderInfo.from_raw(key, res_id, seed)
                    holder: HolderAccountModel = await core_api_client.get_holder_account(op_info.address)
                    balance = await _balance(holder.size)
                    key_total_balance += balance
                    total_balance += balance

                    print(
                        "  {}: status={}, tx={}, size={} bytes, balance={:.9f} SOLs".format(
                            holder.address,
                            holder.status.name,
                            holder.neon_tx_hash,
                            holder.size,
                            balance / (10**9),
                        )
                    )

                print("total {}: {:.9f} SOLs".format(key, key_total_balance / (10**9)))
                print()

            print("total: {:.9f} SOLs".format(total_balance / (10**9)))
        return 0

    async def _destroy_cmd(self, arg_space) -> int:
        core_api_client: CoreApiClient = await self._get_core_api_client()
        op_client: OpResourceClient = await self._get_op_client()

        req_id = self._gen_req_id()
        with logging_context(**req_id):
            holder_addr = SolPubKey.from_raw(arg_space.holder)

            holder: HolderAccountModel = await core_api_client.get_holder_account(holder_addr)
            if holder.status == HolderAccountStatus.Empty:
                _LOG.error("holder %s doesn't exist", holder_addr)
                return 1

            key_list = await op_client.get_signer_key_list(req_id)
            if holder.owner not in key_list:
                _LOG.error("unknown Holder owner %s", holder.owner)
                return 1

            await op_client.destroy_holder(req_id, holder.owner, holder.address)

        return 0

    @cached_property
    def _cu_price(self) -> int:
        return self._cfg.simple_cu_price or 10_000

    async def _cancel_cmd_impl(
        self,
        req_id: dict,
        holder: HolderAccountModel,
        op_res: OpResourceModel,
        timeout_sec: int,
    ) -> bool:
        cancel_tx = await self._make_cancel_tx(holder, op_res)
        if not (alt := await self._create_alt(req_id, op_res.owner, cancel_tx, timeout_sec)):
            return False
        cancel_tx = SolV0Tx(name=cancel_tx.name, ix_list=cancel_tx.ix_list, alt_list=tuple([alt]))

        await self._send_tx_list(req_id, op_res.owner, tuple([cancel_tx]), timeout_sec)
        return True

    async def _make_cancel_tx(self, holder: HolderAccountModel, op_res: OpResourceModel) -> SolLegacyTx:
        acct_meta_list = tuple(
            map(lambda x: SolAccountMeta(x, is_signer=False, is_writable=True), holder.account_key_list)
        )

        cb_prog = SolCbProg()
        cu_price_ix = cb_prog.make_cu_price_ix(self._cu_price)
        cu_limit_ix = cb_prog.make_cu_limit_ix(cb_prog.MaxCuLimit)
        heap_size_ix = cb_prog.make_heap_size_ix(cb_prog.MaxHeapSize)

        core_api_client: CoreApiClient = await self._get_core_api_client()
        evm_cfg = await core_api_client.get_evm_cfg()

        NeonProg.init_prog(evm_cfg.treasury_pool_cnt, evm_cfg.treasury_pool_seed, evm_cfg.version)
        neon_prog = NeonProg(op_res.owner)
        # fmt: off
        neon_prog.init_neon_tx(
            holder.neon_tx_hash, bytes()
        ).init_holder_address(
            holder.address
        ).init_token_address(
            op_res.token_sol_address
        ).init_account_meta_list(
            acct_meta_list
        )
        # fmt: on

        cancel_ix = neon_prog.make_cancel_ix()

        ix_list = tuple([cu_price_ix, cu_limit_ix, heap_size_ix, cancel_ix])
        return SolLegacyTx(NeonEvmIxCode.CancelWithHash.name, ix_list=ix_list)

    async def _create_alt(
        self,
        req_id: dict,
        payer: SolPubKey,
        legacy_tx: SolLegacyTx,
        timeout_sec: int,
    ) -> SolAltInfo | None:
        sol_client: SolClient = await self._get_sol_client()

        alt_tx_builder = SolAltTxBuilder(sol_client, payer, self._cu_price)
        alt: SolAltInfo = await alt_tx_builder.build_alt(legacy_tx, tuple())
        alt_tx_set = alt_tx_builder.build_alt_tx_set(alt)

        for tx_list in alt_tx_set.tx_list_list:
            await self._send_tx_list(req_id, payer, tx_list, timeout_sec)

            await alt_tx_builder.update_alt(alt)
            if not alt.is_exist:
                _LOG.error("fail to create ALT %s", alt.address)
                return None

        return alt

    async def _send_tx_list(self, req_id: dict, payer: SolPubKey, tx_list: Sequence[SolTx], timeout_sec: int) -> None:
        sol_client: SolClient = await self._get_sol_client()
        op_client: OpResourceClient = await self._get_op_client()
        blockhash, _ = await sol_client.get_recent_blockhash(commit=SolCommit.Finalized)

        for tx in tx_list:
            tx.set_recent_blockhash(blockhash)

        tx_list = await op_client.sign_sol_tx_list(req_id, payer, tx_list)
        await sol_client.send_tx_list(tx_list, skip_preflight=False, max_retry_cnt=None)
        await asyncio.sleep(timeout_sec)

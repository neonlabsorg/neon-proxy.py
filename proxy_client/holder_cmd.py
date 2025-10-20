import itertools
import logging
from typing import Final

from typing_extensions import Self

from common.config.config import Config
from common.neon.cancel_error import CancelErrorSource, NeonProxyCancelErrorCode, CancelErrorData
from common.neon.neon_program import NeonProg, NeonEvmIxCode, NeonBaseTxAccountSet
from common.neon_rpc.api import HolderAccountStatus, HolderAccountModel
from common.neon_rpc.client import CoreApiClient
from common.solana.alt_info import SolAltInfo
from common.solana.cb_program import SolCbProg
from common.solana.instruction import SolAccountMeta, SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.transaction_legacy import SolLegacyTx
from common.solana.transaction_v0 import SolV0Tx
from common.solana_rpc.alt_builder import SolAltTxBuilder
from common.solana_rpc.client import SolClient
from common.solana_rpc.ws_client import SolWatchSlotSession
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from proxy.base.op_api import OpResourceModel
from proxy.base.op_client import OpResourceClient
from .cmd_handler import BaseNPCmdHandler
from .common_holder import OpHolderFunc

_LOG = logging.getLogger(__name__)


class HolderHandler(BaseNPCmdHandler):
    command = "holder"
    #
    # protected:
    _list: Final[str] = "list"
    _info: Final[str] = "info"
    _cancel: Final[str] = "cancel"
    _destroy: Final[str] = "destroy"
    _unblock: Final[str] = "unblock"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_func = OpHolderFunc()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(
            self.command,
            description="Commands on Holder accounts",
        )
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_parser = self._cmd_parser.add_parser(self._list, help="list Holder accounts")
        self._subcmd_dict[self._list] = self._list_cmd
        self._holder_func.init_list_cmd(cfg, self._list_parser)

        self._info_parser = self._cmd_parser.add_parser(self._info, help="detailed information about Holder account")
        self._subcmd_dict[self._info] = self._info_cmd
        self._holder_func.init_info_cmd(self._info_parser)

        self._cancel_parser = self._cmd_parser.add_parser(cls._cancel, help="cancel a Neon transaction in a Holder")
        self._subcmd_dict[cls._cancel] = self._cancel_cmd
        self._cancel_parser.add_argument(
            "holder",
            type=str,
            nargs="?",
            help="address of the Holder",
        )
        self._cancel_parser.add_argument(
            "timeout",
            type=int,
            default=3,
            nargs="?",
            help="timeout in seconds to wait the result from Solana",
        )
        self._holder_func.init_list_cmd(self._cfg, self._cancel_parser)

        self._destroy_parser = self._cmd_parser.add_parser(cls._destroy, help="destroy a Holder")
        self._subcmd_dict[self._destroy] = self._destroy_cmd
        self._destroy_parser.add_argument(
            "holder",
            type=str,
            nargs="?",
            help="address of the Holder",
        )

        self._unblock_parser = self._cmd_parser.add_parser(cls._unblock, help="unblock a blocked Holder")
        self._subcmd_dict[self._unblock] = self._unblock_cmd
        self._unblock_parser.add_argument(
            "holder",
            type=str,
            nargs="?",
            help="address of the Holder",
        )

        return self

    async def _list_cmd(self, arg_space) -> int:
        cmd = self._holder_func.parse_list_cmd(arg_space)
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            op_client: OpResourceClient = await self._get_op_client()
            core_api_client: CoreApiClient = await self._get_core_api_client()
            sol_client: SolClient = await self._get_sol_client()
            signer_key_list = await op_client.get_signer_key_list(req_id)
            await self._holder_func.print_holder_list(core_api_client, sol_client, signer_key_list, cmd)
        return 0

    async def _info_cmd(self, arg_space) -> int:
        cmd = self._holder_func.parse_info_cmd(arg_space)
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            core_api_client: CoreApiClient = await self._get_core_api_client()
            sol_client: SolClient = await self._get_sol_client()
            await self._holder_func.print_holder(core_api_client, sol_client, cmd)
        return 0

    async def _cancel_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            timeout_sec = arg_space.timeout

            core_api_client: CoreApiClient = await self._get_core_api_client()
            op_client: OpResourceClient = await self._get_op_client()

            status = HolderAccountStatus

            if str(arg_space.holder).upper() == "ALL":
                signer_key_list = await op_client.get_signer_key_list(req_id)
                cmd = self._holder_func.parse_list_cmd(arg_space)
                holder_list = await self._holder_func.get_holder_list(core_api_client, signer_key_list, cmd)

                holder_addr_list: list[SolPubKey] = list()
                for holder in holder_list:
                    if holder.status in (status.Active, status.ScheduledCanceled, status.ScheduledFinalized):
                        holder_addr_list.append(holder.address)

                if not holder_addr_list:
                    print("no stuck transactions found")
                    return 0
            else:
                holder_addr_list = [SolPubKey.from_raw(arg_space.holder)]

            for holder_addr in holder_addr_list:
                holder = await core_api_client.get_holder_account(holder_addr)
                if holder.status == HolderAccountStatus.Active:
                    if not (await self._cancel_tx(req_id, holder, timeout_sec)):
                        return 1
                    holder = await core_api_client.get_holder_account(holder_addr)

                if holder.status in (HolderAccountStatus.ScheduledCanceled, HolderAccountStatus.ScheduledFinalized):
                    if not (await self._finish_skd_tx(req_id, holder, timeout_sec)):
                        return 1
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

    async def _unblock_cmd(self, arg_space) -> int:
        op_client: OpResourceClient = await self._get_op_client()

        req_id = self._gen_req_id()
        with logging_context(**req_id):
            holder_addr = SolPubKey.from_raw(arg_space.holder)
            if await op_client.unblock_holder(req_id, holder_addr):
                _LOG.debug("holder %s is unblocked", holder_addr)
            else:
                _LOG.warning("holder %s can't be unblocked", holder_addr)
                return 1
        return 0

    def _get_cb_ix_list(self, cu_limit=SolCbProg.MaxCuLimit // 2) -> list[SolTxIx]:
        cb_prog = SolCbProg()
        cu_price_ix = cb_prog.make_cu_price_ix(self._cu_price)
        cu_limit_ix = cb_prog.make_cu_limit_ix(cu_limit)
        heap_size_ix = cb_prog.make_heap_size_ix(cb_prog.MaxHeapSize)
        return [cu_price_ix, cu_limit_ix, heap_size_ix]

    @cached_property
    def _cu_price(self) -> int:
        return self._cfg.def_simple_cu_price

    async def _cancel_tx(
        self,
        req_id: dict,
        holder: HolderAccountModel,
        timeout_sec: int,
    ) -> bool:
        print("Holder %s has the active NeonTx %s" % (holder.address, holder.neon_tx_hash))

        op_client: OpResourceClient = await self._get_op_client()
        core_api_client: CoreApiClient = await self._get_core_api_client()

        if (op_res := await op_client.get_resource(req_id, holder.chain_id, holder.owner, holder.address)).is_empty:
            _LOG.error("no available resource to process the NeonTx canceling")
            return False

        try:
            for retry in itertools.count():
                if retry > 10:
                    print("fail to cancel Holder %s after 10 retries" % holder.address)
                    return False

                cancel_tx = await self._make_cancel_tx(holder, op_res)
                if not (alt := await self._create_alt(req_id, op_res.owner, cancel_tx, timeout_sec)):
                    return False
                cancel_tx = SolV0Tx(name=cancel_tx.name, ix_list=cancel_tx.ix_list, alt_list=tuple([alt]))
                await self._send_tx_list(req_id, op_res.owner, tuple([cancel_tx]), timeout_sec)

                holder = await core_api_client.get_holder_account(holder.address)
                if holder.status == HolderAccountStatus.Active:
                    _LOG.warning("Holder %s has the active NeonTx %s", holder.address, holder.neon_tx_hash)
                    continue

                print("done canceling Holder %s" % holder.address)
                return True
        except BaseException as exc:
            _LOG.error("got error %s", str(exc))

        finally:
            await op_client.free_resource(req_id, True, op_res)

        return False

    async def _make_cancel_tx(self, holder: HolderAccountModel, op_res: OpResourceModel) -> SolLegacyTx:
        acct_meta_list = tuple(
            map(lambda x: SolAccountMeta(x, is_signer=False, is_writable=True), holder.account_key_list)
        )

        core_api_client: CoreApiClient = await self._get_core_api_client()
        neon_acct = await core_api_client.get_neon_account(holder.payer, None)

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
        ).init_tx_sol_address(
            NeonBaseTxAccountSet(
                payer=neon_acct.sol_address,
                sender=neon_acct.sol_address,
                receiver=SolPubKey.default(),
                receiver_contract=SolPubKey.default(),
                payer_balance=0
            )
        )
        # fmt: on

        data = CancelErrorData(CancelErrorSource.NeonProxy, NeonProxyCancelErrorCode.Manual, "Unknown")
        cancel_ix = neon_prog.make_cancel_ix(data.to_bytes())

        ix_list = self._get_cb_ix_list() + [cancel_ix]
        return SolLegacyTx(NeonEvmIxCode.CancelWithHash.name, ix_list=ix_list)

    async def _create_alt(
        self,
        req_id: dict,
        payer: SolPubKey,
        legacy_tx: SolLegacyTx,
        timeout_sec: int,
    ) -> SolAltInfo | None:
        sol_client: SolClient = await self._get_sol_client()

        slot_session = SolWatchSlotSession(self._cfg, sol_client)
        await slot_session.start()

        alt_tx_builder = SolAltTxBuilder(self._cfg, sol_client, slot_session, payer, self._cu_price)
        fake_alt: SolAltInfo = alt_tx_builder.build_fake_alt(legacy_tx)
        alt: SolAltInfo = await alt_tx_builder.rebuild_to_real_alt(fake_alt)
        alt_tx_set = alt_tx_builder.build_alt_tx_set(alt)

        for tx_list in alt_tx_set.tx_list_list:
            await self._send_tx_list(req_id, payer, tx_list, timeout_sec)

            await alt_tx_builder.update_alt(alt)
            if not alt.is_exist:
                _LOG.error("fail to create ALT %s", alt.address)
                return None

        await slot_session.stop()
        return alt

    async def _finish_skd_tx(
        self,
        req_id: dict,
        holder: HolderAccountModel,
        timeout_sec: int,
    ) -> bool:
        print("Holder %s has the scheduled NeonTx %s" % (holder.address, holder.neon_tx_hash))

        op_client: OpResourceClient = await self._get_op_client()
        core_api_client: CoreApiClient = await self._get_core_api_client()

        if (op_res := await op_client.get_resource(req_id, holder.chain_id, holder.owner, holder.address)).is_empty:
            _LOG.error("no available resource to process the NeonSkdTx finishing")
            return False

        try:
            for retry in itertools.count():
                if retry > 10:
                    print("fail to finish NeonSkdTx in the Holder %s after 10 retries" % holder.address)
                    return False

                if not (tx_list := await self._make_finish_skd_tx(holder, op_res)):
                    return True

                finish_tx, destroy_tx = tx_list
                await self._send_tx_list(req_id, op_res.owner, tuple([finish_tx]), timeout_sec)

                holder = await core_api_client.get_holder_account(holder.address)
                if holder.status in (HolderAccountStatus.ScheduledCanceled, HolderAccountStatus.ScheduledFinalized):
                    _LOG.warning("Holder %s has the active NeonSkdTx %s", holder.address, holder.neon_tx_hash)
                    continue

                print("try to destroy Tree...")
                await self._send_tx_list(req_id, op_res.owner, tuple([destroy_tx]), timeout_sec)

                print("done finish Holder %s" % holder.address)
                return True
        except BaseException as exc:
            _LOG.error("got error %s", str(exc), exc_info=True)

        finally:
            await op_client.free_resource(req_id, True, op_res)

        return False

    async def _make_finish_skd_tx(
        self, holder: HolderAccountModel, op_res: OpResourceModel
    ) -> None | tuple[SolLegacyTx, SolLegacyTx]:
        core_api_client: CoreApiClient = await self._get_core_api_client()

        if not (skd_tree_acct := await core_api_client.get_neon_skd_tree(holder.payer, holder.tx.nonce)).is_exist:
            print("NeonSkdTree %s:%s doesn't exist" % (holder.payer, holder.tx.nonce))
            return None

        if not (skd_node_idx := skd_tree_acct.find_neon_skd_node(holder.neon_tx_hash)):
            print("NeonTx %s doesn't exist in %s" % (holder.neon_tx_hash, skd_tree_acct.address))
            return None

        neon_acct = await core_api_client.get_neon_account(holder.payer, None)

        neon_prog = NeonProg(op_res.owner)

        # fmt: off
        neon_prog.init_neon_tx(
            holder.neon_tx_hash, bytes()
        ).init_holder_address(
            holder.address
        ).init_token_address(
            op_res.token_sol_address
        ).init_skd_tree_address(
            skd_tree_acct.address
        ).init_tx_sol_address(
            NeonBaseTxAccountSet(
                payer=neon_acct.sol_address,
                sender=neon_acct.sol_address,
                receiver=SolPubKey.default(),
                receiver_contract=SolPubKey.default(),
                payer_balance=0
            )
        )
        # fmt: on

        skd_tx_idx = skd_node_idx[0]
        finish_ix = neon_prog.make_finish_skd_tx_ix(skd_tx_idx)
        destroy_ix = neon_prog.make_destroy_skd_tree_ix()

        finish_ix_list = self._get_cb_ix_list() + [finish_ix]
        finish_tx = SolLegacyTx(NeonEvmIxCode.SkdTxFinish.name, ix_list=finish_ix_list)

        destroy_ix_list = self._get_cb_ix_list(neon_prog.CuLimitSkdTreeAccountDestroy) + [destroy_ix]
        destroy_tx = SolLegacyTx(NeonEvmIxCode.SkdTreeDestroy.name, ix_list=destroy_ix_list)
        return finish_tx, destroy_tx

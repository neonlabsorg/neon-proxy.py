import asyncio
import logging
from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from common.solana.alt_program import SolAltProg, SolAltIxCode, SolAltID
from common.solana.cb_program import SolCbProg
from common.solana.commit_level import SolCommit
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.transaction_legacy import SolLegacyTx
from common.utils.cached import cached_property
from common.utils.json_logger import logging_context
from .cmd_handler import BaseNPCmdHandler
from .common_alt import SolAltFunc

_LOG = logging.getLogger(__name__)


class AltHandler(BaseNPCmdHandler):
    command: ClassVar[str] = "alt"
    #
    # protected:
    _list: Final[str] = "list"
    _info: Final[str] = "info"
    _destroy: Final[str] = "destroy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._alt_func = SolAltFunc()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(
            self.command,
            description="Commands on Address Lookup Tables",
        )
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_parser = self._cmd_parser.add_parser(cls._list, help="list Address Lookup Tables")
        self._subcmd_dict[cls._list] = self._list_cmd
        self._list_parser.add_argument(
            "owner",
            type=str,
            help="owner of the Address Lookup Table",
        )

        self._info_parser = self._cmd_parser.add_parser(self._info, help="info about Address Lookup Tables")
        self._subcmd_dict[self._info] = self._info_cmd
        self._info_parser.add_argument(
            "address",
            type=str,
            help="address of the Address Lookup Table",
        )

        self._destroy_parser = self._cmd_parser.add_parser(cls._destroy, help="destroy Address Lookup Tables")
        self._subcmd_dict[cls._destroy] = self._destroy_cmd
        self._destroy_parser.add_argument(
            "address",
            type=str,
            help="address of the Address Lookup Table",
        )

        return self

    @cached_property
    def _cu_price(self) -> int:
        return self._cfg.simple_cu_price or 10_000

    async def _list_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()
            op_client = await self._get_op_client()
            await self._alt_func.print_alt_list(req_id, arg_space.owner, op_client, sol_client)
            return 0

    async def _info_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        addr = SolPubKey.from_raw(arg_space.address)
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()
            await self._alt_func.print_alt(sol_client, addr)
        return 0

    async def _destroy_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()
            op_client = await self._get_op_client()

            owner_list = await op_client.get_signer_key_list(req_id)
            if arg_space.address.upper() == "ALL":
                result = 0
                for owner in owner_list:
                    acct_list = await self._alt_func.get_alt_list(sol_client, owner)
                    for acct in acct_list:
                        result += await self._destroy_alt(
                            req_id,
                            owner_list,
                            acct.address,
                        )
                return 1 if result else 0
            else:
                return await self._destroy_alt(
                    req_id,
                    owner_list,
                    SolPubKey.from_raw(arg_space.address),
                )

    async def _destroy_alt(
        self,
        req_id: dict,
        owner_list: tuple[SolPubKey, ...],
        address: SolPubKey,
    ) -> int:
        sol_client = await self._get_sol_client()
        op_client = await self._get_op_client()

        if not (alt := await sol_client.get_alt_account(address)).is_exist:
            _LOG.error("Address Lookup Table %s doesn't exist", address)
            return 1

        if alt.owner not in owner_list:
            _LOG.error("Address Lookup Table %s has unknown owner %s", address, alt.owner)
            return 1

        valid_slot = await sol_client.get_slot(SolCommit.Finalized)
        valid_slot -= 10_000

        if alt.last_extended_slot > valid_slot:
            _LOG.error("Address Lookup Table %s is too young (%s > %s)", address, alt.last_extended_slot, valid_slot)
            return 1

        cb_prog = SolCbProg()

        cu_price_ix = cb_prog.make_cu_price_ix(self._cu_price)
        cu_limit_ix = cb_prog.make_cu_limit_ix(10_000)

        ix_list: list[SolTxIx] = [cu_price_ix, cu_limit_ix]
        alt_id = SolAltID(address=alt.address, owner=alt.owner, recent_slot=0, nonce=0)
        if not alt.is_deactivated:
            name = SolAltIxCode.Deactivate.name + "LookupTable"
            ix_list.append(SolAltProg(alt.owner).make_deactivate_alt_ix(alt_id))
            _LOG.debug("deactivate Address Lookup Table %s", address)
        else:
            name = SolAltIxCode.Close.name + "LookupTable"
            ix_list.append(SolAltProg(alt.owner).make_close_alt_ix(alt_id))
            _LOG.debug("close Address Lookup Table %s", address)

        blockhash, _ = await sol_client.get_recent_blockhash(SolCommit.Finalized)
        tx = SolLegacyTx(name=name, ix_list=ix_list, blockhash=blockhash)

        tx_list = await op_client.sign_sol_tx_list(req_id, alt.owner, [tx])
        await sol_client.send_tx_list(tx_list, skip_preflight=False, max_retry_cnt=None)
        await asyncio.sleep(1)

        return 0

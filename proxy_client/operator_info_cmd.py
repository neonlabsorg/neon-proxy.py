from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context
from .cmd_handler import BaseNPCmdHandler
from .common_alt import SolAltFunc


class OpInfoHandler(BaseNPCmdHandler, SolAltFunc):
    command: ClassVar[str] = "operator-info"
    #
    # protected:
    _list_sol: Final[str] = "list-solana-addresses"
    _list_neon: Final[str] = "list-neon-addresses"
    _list_alt: Final[str] = "list-alt-addresses"

    _alt_meta_auth_offset: Final[int] = 22

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(self.command)
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_sol_parser = self._cmd_parser.add_parser(cls._list_sol, help="list Solana addresses")
        self._subcmd_dict[cls._list_sol] = self._list_sol_cmd

        self._list_neon_parser = self._cmd_parser.add_parser(cls._list_neon, help="list Neon addresses")
        self._subcmd_dict[cls._list_neon] = self._list_neon_cmd

        self._list_alt_parser = self._cmd_parser.add_parser(cls._list_alt, help="list Address Lookup Tables")
        self._subcmd_dict[cls._list_alt] = self._list_alt_cmd
        self._list_alt_parser.add_argument(
            "owner",
            type=str,
            help="owner of the Address Lookup Table",
        )
        return self

    async def _list_sol_cmd(self, _arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            op_client = await self._get_op_client()
            addr_list = await op_client.get_signer_key_list(req_id)
            for addr in addr_list:
                print(f"{addr}")
            return 0

    async def _list_neon_cmd(self, _arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            op_client = await self._get_op_client()
            addr_list = await op_client.get_eth_address_list(req_id)
            for addr in addr_list:
                print(f"{addr.eth_address}\t{addr.owner}")
            return 0

    async def _list_alt_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()

            if arg_space.owner == "ALL":
                op_client = await self._get_op_client()
                await self.print_all_alt(req_id, op_client, sol_client)
            else:
                owner = SolPubKey.from_raw(arg_space.owner)
                await self.print_alt_by_owner(sol_client, owner, False)

            return 0

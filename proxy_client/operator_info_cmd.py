from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from common.neon_rpc.client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from common.utils.json_logger import logging_context
from proxy.base.op_client import OpResourceClient
from .cmd_handler import BaseNPCmdHandler
from .common_alt import SolAltFunc
from .common_holder import OpHolderFunc


class OpInfoHandler(BaseNPCmdHandler):
    command: ClassVar[str] = "operator-info"
    #
    # protected:
    _list_sol: Final[str] = "list-solana-addresses"
    _list_neon: Final[str] = "list-neon-addresses"
    _list_alt: Final[str] = "list-alts"
    _info_alt: Final[str] = "alt-info"
    _list_holder: Final[str] = "list-holders"
    _info_holder: Final[str] = "holder-info"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._alt_func = SolAltFunc()
        self._holder_func = OpHolderFunc()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(
            self.command,
            description="Information commands",
        )
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_sol_parser = self._cmd_parser.add_parser(cls._list_sol, help="list Solana addresses")
        self._subcmd_dict[cls._list_sol] = self._list_sol_cmd

        self._list_neon_parser = self._cmd_parser.add_parser(cls._list_neon, help="list Neon addresses")
        self._subcmd_dict[cls._list_neon] = self._list_neon_cmd

        self._list_holder_parser = self._cmd_parser.add_parser(self._list_holder, help="list Holder accounts")
        self._holder_func.init_list_cmd(cfg, self._list_holder_parser)
        self._subcmd_dict[self._list_holder] = self._list_holder_cmd

        self._info_holder_parser = self._cmd_parser.add_parser(
            self._info_holder, help="detailed information about Holder account"
        )
        self._holder_func.init_info_cmd(self._info_holder_parser)
        self._subcmd_dict[self._info_holder] = self._info_holder_cmd

        self._list_alt_parser = self._cmd_parser.add_parser(cls._list_alt, help="list Address Lookup Tables")
        self._subcmd_dict[cls._list_alt] = self._list_alt_cmd
        self._list_alt_parser.add_argument(
            "owner",
            type=str,
            help="owner of the Address Lookup Table",
        )

        self._info_alt_parser = self._cmd_parser.add_parser(
            cls._info_alt,
            help="detailed information about Address Lookup Table",
        )
        self._subcmd_dict[cls._info_alt] = self._info_alt_cmd
        self._info_alt_parser.add_argument(
            "address",
            type=str,
            help="address of the Address Lookup Table",
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

    async def _list_holder_cmd(self, arg_space) -> int:
        cmd = self._holder_func.parse_list_cmd(arg_space)
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client: SolClient = await self._get_sol_client()
            op_client: OpResourceClient = await self._get_op_client()
            core_api_client: CoreApiClient = await self._get_core_api_client()
            signer_key_list = await op_client.get_signer_key_list(req_id)
            await self._holder_func.print_holder_list(core_api_client, sol_client, signer_key_list, cmd)
        return 0

    async def _info_holder_cmd(self, arg_space) -> int:
        cmd = self._holder_func.parse_info_cmd(arg_space)
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client: SolClient = await self._get_sol_client()
            core_api_client: CoreApiClient = await self._get_core_api_client()
            await self._holder_func.print_holder(core_api_client, sol_client, cmd)
        return 0

    async def _list_alt_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()
            op_client = await self._get_op_client()
            await self._alt_func.print_alt_list(req_id, arg_space.owner, op_client, sol_client)
        return 0

    async def _info_alt_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        addr = SolPubKey.from_raw(arg_space.address)
        with logging_context(**req_id):
            sol_client = await self._get_sol_client()
            await self._alt_func.print_alt(sol_client, addr)
        return 0

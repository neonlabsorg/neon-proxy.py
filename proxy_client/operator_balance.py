import logging
from dataclasses import dataclass
from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context
from .base_handler import BaseHandler

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _OpBalance:
    owner: SolPubKey
    eth_address: EthAddress
    token_balance_dict: dict[str, int]


class OpBalanceHandler(BaseHandler):
    command: ClassVar[str] = "operator-balance"
    _percent: Final[str] = "PERCENT"
    _percent_postfix: Final[str] = "_PERCENT"
    _list: Final[str] = "list-earned-tokens"
    _withdraw: Final[str] = "withdraw-earned-tokens"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._token_list: list[str] = list()

    @classmethod
    async def new_arg_parser(cls, cfg: Config, action) -> Self:
        self = cls(cfg)
        self._root_parser = action.add_parser(self.command)
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_parser = self._cmd_parser.add_parser(cls._list, help="list the balances of earned tokens")
        self._subcmd_dict[cls._list] = self._list_cmd

        self._withdraw_parser = self._cmd_parser.add_parser(cls._withdraw, help="withdraw earned tokens")

        mp_client = await self._get_mp_client()
        evm_cfg = await mp_client.get_evm_cfg()
        token_list = list(evm_cfg.token_dict.keys())

        self._withdraw_parser.add_argument(
            "dest_address",
            type=str,
            default=None,
            nargs="?",
            help="destination address for withdraw",
        )
        self._withdraw_parser.add_argument(
            "amount",
            type=int,
            default=0,
            nargs="?",
            help="withdrawing amount",
        )

        self._token_list = "|".join(token_list + [name + cls._percent_postfix for name in token_list])
        self._withdraw_parser.add_argument(
            "type",
            type=str,
            default=cls._percent,
            nargs="?",
            help=f"type of amount <{cls._percent}|{self._token_list}>",
        )

        self._subcmd_dict[cls._withdraw] = self._withdraw_cmd
        return self

    async def _list_cmd(self, _arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            op_balance_list = await self._get_earned_token_balance(req_id)
            total_balance_dict: dict[str, int] = dict()

            for op_balance in op_balance_list:
                print(f"{op_balance.eth_address} ({op_balance.owner}):")
                for token, balance in op_balance.token_balance_dict.items():
                    total_balance_dict[token] = total_balance_dict.get(token, 0) + balance
                    balance = balance / (10**18)
                    balance = f"{balance:,.18f}".replace(",", "'")
                    print(f"\t{balance} {token}")

            print()
            print("total balance:")
            for token_name, balance in total_balance_dict.items():
                balance = balance / (10**18)
                balance = f"{balance:,.18f}".replace(",", "'")
                print(f"\t{balance} {token_name}")

        return 0

    async def _withdraw_cmd(self, arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
            dest_addr = EthAddress.from_raw(arg_space.dest_address) if arg_space.dest_address else None
            t_amount = arg_space.amount
            op_balance_list = await self._get_earned_token_balance(req_id)
            token_balance_dict: dict[str, int] = dict()

            if dest_addr:
                token_set = set(self._token_list)
                t_type: str = arg_space.type.upper()
                if t_type not in token_set:
                    _LOG.error("wrong type of amount type %s, should be %s", t_type, ", ".join(sorted(token_set)))
                    return 1
                elif t_amount <= 0:
                    _LOG.error("amount %s, should be an positive number", t_amount)
                    return 1
                elif t_amount > 100 and (t_type == self._percent or t_type.endswith(self._percent_postfix)):
                    _LOG.error("amount %s is too big, should be less or equal 100", t_amount)
                    return 1

                for op_balance in op_balance_list:
                    for token, balance in op_balance.token_balance_dict.items():
                        token_balance_dict[token] = token_balance_dict.get(token, 0) + balance

                if t_type == self._percent:
                    for token, balance in token_balance_dict.items():
                        token_balance_dict[token] = int(balance * t_amount / 100)
                elif t_type.endswith(self._percent_postfix):
                    token = t_type[: -len(self._percent_postfix)]
                    balance = token_balance_dict.get(token, 0)
                    token_balance_dict = {token: int(balance * t_amount / 100)}
                else:
                    token = t_type
                    balance = token_balance_dict.get(token, 0)
                    token_balance_dict = {token: int(balance)}

                    check_balance = int(balance / (10**18)) + 1
                    if check_balance < t_amount:
                        _LOG.error("amount %s is too big, should be less than %s", t_amount, check_balance)
                        return 1

            op_client = await self._get_op_client()
            await op_client.withdraw()
        return 0

    async def _get_earned_token_balance(self, req_id: dict) -> tuple[_OpBalance, ...]:
        mp_client = await self._get_mp_client()
        op_client = await self._get_op_client()
        core_api_client = await self._get_core_api_client()

        evm_cfg = await mp_client.get_evm_cfg()
        eth_address_list = await op_client.get_eth_address_list(req_id)

        op_balance_list: list[_OpBalance] = list()
        for op_addr in eth_address_list:
            token_balance_dict: dict[str, int] = dict()
            for chain_id, token in evm_cfg.chain_dict.items():
                neon_acct = NeonAccount.from_raw(op_addr.eth_address, chain_id)

                neon_balance = await core_api_client.get_neon_account(neon_acct, None)
                op_balance = await core_api_client.get_operator_account(evm_cfg, op_addr.owner, neon_acct, None)

                balance = neon_balance.balance + op_balance.balance
                token_balance_dict[token.name] = balance

            balance = _OpBalance(op_addr.owner, op_addr.eth_address, token_balance_dict)
            op_balance_list.append(balance)

        return tuple(op_balance_list)

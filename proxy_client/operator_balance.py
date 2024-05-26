from dataclasses import dataclass
from typing import ClassVar, Final

from typing_extensions import Self

from common.config.config import Config
from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context
from .base_handler import BaseHandler


@dataclass(frozen=True)
class _OpBalance:
    owner: SolPubKey
    eth_address: EthAddress
    token_balance_dict: dict[str, int]


class OpBalanceHandler(BaseHandler):
    command: ClassVar[str] = "operator-balance"
    _list: Final[str] = "list-earned-tokens"
    _withdraw: Final[str] = "withdraw-earned-tokens"

    @classmethod
    def new_arg_parser(cls, cfg: Config, action) -> Self:
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

    async def _withdraw_cmd(self, _arg_space) -> int:
        req_id = self._gen_req_id()
        with logging_context(**req_id):
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
                token_balance_dict[token] = balance

            balance = _OpBalance(op_addr.owner, op_addr.eth_address, token_balance_dict)
            op_balance_list.append(balance)

        return tuple(op_balance_list)

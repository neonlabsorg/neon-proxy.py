import logging
from dataclasses import dataclass
from typing import ClassVar, Final, Sequence

from typing_extensions import Self

from common.config.config import Config
from common.ethereum.bin_str import EthBinStr
from common.ethereum.hash import EthAddress, EthTxHash
from common.neon.account import NeonAccount
from common.neon.transaction_model import NeonTxModel
from common.neon_rpc.api import EvmConfigModel, NeonAccountStatus
from common.solana.pubkey import SolPubKey
from common.utils.json_logger import logging_context
from proxy.base.mp_api import MpTxRespCode
from .cmd_handler import BaseNPCmdHandler

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _OpBalance:
    owner: SolPubKey
    eth_address: EthAddress
    token_balance_dict: dict[int, int]


class OpBalanceHandler(BaseNPCmdHandler):
    command: ClassVar[str] = "operator-balance"
    #
    # protected:
    _percent: Final[str] = "PERCENT"
    _percent_postfix: Final[str] = "_PERCENT"
    _list: Final[str] = "list-earned-tokens"
    _withdraw: Final[str] = "withdraw-earned-tokens"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._token_list: list[str] = list()
        self._evm_cfg: EvmConfigModel | None = None

    @classmethod
    async def new_arg_parser(cls, cfg: Config, cmd_list_parser) -> Self:
        self = cls(cfg)
        self._root_parser = cmd_list_parser.add_parser(self.command)
        self._cmd_parser = self._root_parser.add_subparsers(
            title="command",
            dest="subcommand",
            description="valid commands",
        )

        self._list_parser = self._cmd_parser.add_parser(cls._list, help="list the balances of earned tokens")
        self._subcmd_dict[cls._list] = self._list_cmd

        self._withdraw_parser = self._cmd_parser.add_parser(cls._withdraw, help="withdraw earned tokens")

        mp_client = await self._get_mp_client()
        self._evm_cfg = await mp_client.get_evm_cfg()
        token_list = list(self._evm_cfg.token_dict.keys())

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

        self._token_list = [self._percent] + token_list + [name + cls._percent_postfix for name in token_list]
        token_list_str = "|".join(self._token_list)
        self._withdraw_parser.add_argument(
            "type",
            type=str,
            default=cls._percent,
            nargs="?",
            help=f"type of amount <{token_list_str}>",
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
                for chain_id, balance in op_balance.token_balance_dict.items():
                    token = self._evm_cfg.chain_dict[chain_id].name
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
            t_type = arg_space.type.upper()
            token_set = set(self._token_list)

            if t_type not in token_set:
                _LOG.error("wrong type of amount type %s, should be %s", t_type, ", ".join(sorted(token_set)))
                return 1
            elif t_amount <= 0:
                _LOG.error("amount %s, should be an positive number", t_amount)
                return 1
            elif t_amount > 100 and (t_type == self._percent or t_type.endswith(self._percent_postfix)):
                _LOG.error("amount %s is too big, should be less or equal 100", t_amount)
                return 1
            elif (not dest_addr) and t_amount:
                _LOG.error("destination address should be defined on amount > 0")
                return 1

            op_balance_list = await self._get_earned_token_balance(req_id)
            token_balance_dict = self._build_token_balance_dict(op_balance_list, t_amount, t_type)
            if not token_balance_dict:
                return 1

            op_client = await self._get_op_client()
            chain_list = [chain_id for chain_id, balance in token_balance_dict.items() if balance > 0]
            await op_client.withdraw(req_id, chain_list)

            if not dest_addr:
                return 0

            for chain_id, total_balance in token_balance_dict.items():
                balance = total_balance
                op_balance_list.sort(key=lambda x: x.token_balance_dict.get(chain_id, 0), reverse=True)
                for op_balance in op_balance_list:
                    if (value := min(op_balance.token_balance_dict.get(chain_id, 0), balance)) > 0:
                        if not await self._send_value(req_id, op_balance.eth_address, dest_addr, chain_id, value):
                            return 1
                        balance -= value
                    else:
                        break

                token = self._evm_cfg.chain_dict[chain_id].name
                total_balance = total_balance / (10 ** 18)
                # fmt: off
                print(
                    f"successfully send {total_balance:,.18} {token} " 
                    f"to {dest_addr.to_checksum()}"
                )
                # fmt: on

        return 0

    async def _send_value(
        self,
        req_id: dict,
        sender_addr: EthAddress,
        dest_addr: EthAddress,
        chain_id: int,
        value: int,
    ) -> bool:
        core_api_client = await self._get_core_api_client()
        op_client = await self._get_op_client()
        mp_client = await self._get_mp_client()
        token = self._evm_cfg.chain_dict[chain_id].name

        dest_acct = await core_api_client.get_neon_account(NeonAccount.from_raw(dest_addr, chain_id), None)
        if dest_acct.status == NeonAccountStatus.Empty:
            gas_limit = 2_000_000
        else:
            gas_limit = 25_000

        state_tx_cnt = await core_api_client.get_state_tx_cnt(NeonAccount.from_raw(sender_addr, chain_id))
        tx = NeonTxModel(
            tx_type=0,
            neon_tx_hash=EthTxHash.default(),
            from_address=sender_addr,
            to_address=dest_addr,
            contract=EthAddress.default(),
            nonce=state_tx_cnt,
            gas_price=0,
            gas_limit=gas_limit,
            value=value,
            call_data=EthBinStr.default(),
            v=0,
            r=0,
            s=0,
        )
        resp = await op_client.sign_eth_tx(req_id, tx, chain_id)
        if resp.error:
            _LOG.error("cannot sign tx: %s", resp.error)
            return False

        eth_tx_rlp = resp.signed_tx.to_bytes()
        ctx = str(req_id["timestamp"])
        tx = NeonTxModel.from_raw(eth_tx_rlp)

        value = value / (10 ** 18)
        print(
            f"send {value:,.18} {token} "
            f"from {sender_addr.to_checksum()} "
            f"to {dest_addr.to_checksum()}: "
            f"{tx.neon_tx_hash.to_string()}"
        )

        resp = await mp_client.send_raw_transaction(ctx, resp.signed_tx.to_bytes(), chain_id, state_tx_cnt)
        if resp.code != MpTxRespCode.Success:
            _LOG.error("fail to send tx: %s", resp.code.name)
            return False

        return True

    def _build_token_balance_dict(
        self,
        op_balance_list: Sequence[_OpBalance],
        t_amount: int,
        t_type: str,
    ) -> dict[int, int]:
        token_balance_dict: dict[int, int] = dict()
        has_balance = False

        for op_balance in op_balance_list:
            for chain_id, balance in op_balance.token_balance_dict.items():
                token_balance_dict[chain_id] = token_balance_dict.get(chain_id, 0) + balance
                has_balance = has_balance or (balance > 0)

        if not has_balance:
            _LOG.error("all balances are empty")
            return dict()

        if not t_amount:
            return token_balance_dict

        if t_type == self._percent:
            for token, balance in token_balance_dict.items():
                token_balance_dict[token] = int(balance * t_amount / 100)
        elif t_type.endswith(self._percent_postfix):
            token = t_type[: -len(self._percent_postfix)]
            chain_id = self._evm_cfg.token_dict[token].chain_id
            balance = token_balance_dict.get(chain_id, 0)
            token_balance_dict = {chain_id: int(balance * t_amount / 100)}
        else:
            token = t_type
            chain_id = self._evm_cfg.token_dict[token].chain_id
            balance = token_balance_dict.get(chain_id, 0)

            check_balance = balance // (10**18) + 1
            if check_balance < t_amount:
                _LOG.error("amount %s is too big, should be less than %s", t_amount, check_balance)
                return dict()

            token_balance_dict = {chain_id: balance}

        return token_balance_dict

    async def _get_earned_token_balance(self, req_id: dict) -> list[_OpBalance]:
        op_client = await self._get_op_client()
        core_api_client = await self._get_core_api_client()

        eth_address_list = await op_client.get_eth_address_list(req_id)

        op_balance_list: list[_OpBalance] = list()
        for op_addr in eth_address_list:
            token_balance_dict: dict[int, int] = dict()
            for chain_id in self._evm_cfg.chain_dict.keys():
                neon_acct = NeonAccount.from_raw(op_addr.eth_address, chain_id)

                neon_balance = await core_api_client.get_neon_account(neon_acct, None)
                earn_balance = await core_api_client.get_earn_account(self._evm_cfg, op_addr.owner, neon_acct, None)

                balance = neon_balance.balance + earn_balance.balance
                token_balance_dict[chain_id] = balance

            balance = _OpBalance(op_addr.owner, op_addr.eth_address, token_balance_dict)
            op_balance_list.append(balance)

        return op_balance_list

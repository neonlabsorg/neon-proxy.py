import json
from dataclasses import dataclass
from typing import Sequence

from common.neon_rpc.api import HolderAccountModel
from common.neon_rpc.client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from proxy.operator_resource.key_info import OpHolderInfo


class OpHolderFunc:
    @staticmethod
    def init_list_cmd(cfg, list_parser) -> None:
        list_parser.add_argument(
            "start",
            type=int,
            nargs="?",
            default=cfg.perm_account_id,
            help="start identifier for Holder",
        )
        list_parser.add_argument(
            "quantity",
            type=int,
            nargs="?",
            default=cfg.perm_account_limit,
            help="number of Holders to list",
        )
        list_parser.add_argument(
            "seed",
            type=str,
            nargs="?",
            default=OpHolderInfo.default_prefix.decode("utf-8"),
            help="seed prefix for the Holder PDA",
        )

    @dataclass(frozen=True)
    class ListCmd:
        start_id: int
        stop_id: int
        seed: bytes

    @classmethod
    def parse_list_cmd(cls, arg_space) -> ListCmd:
        assert arg_space.quantity > 0
        assert arg_space.start >= 0
        assert len(arg_space.seed) > 0

        return cls.ListCmd(
            start_id=arg_space.start,
            stop_id=arg_space.start + arg_space.quantity,
            seed=arg_space.seed.encode("utf-8"),
        )

    @staticmethod
    def init_info_cmd(info_parser) -> None:
        info_parser.add_argument("holder", type=str, nargs="?", help="address of the Holder")

    @dataclass(frozen=True)
    class InfoCmd:
        address: SolPubKey

    @classmethod
    def parse_info_cmd(cls, arg_space) -> InfoCmd:
        return cls.InfoCmd(address=SolPubKey.from_raw(arg_space.holder))

    @classmethod
    async def print_holder_list(
        cls,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        signer_key_list: Sequence[SolPubKey],
        cmd: ListCmd,
    ) -> None:
        total_balance = 0
        holder_list = await cls.get_holder_list(core_api_client, signer_key_list, cmd)

        def _print_key_balance(_key: SolPubKey, _balance: int) -> None:
            if _key.is_empty:
                return

            print("total {}: {:.9f} SOLs".format(_key, _balance / (10 ** 9)))
            print()

        key = SolPubKey.default()
        key_total_balance = 0
        for holder in holder_list:
            if holder.owner != key:
                _print_key_balance(key, key_total_balance)
                #
                key = holder.owner
                key_total_balance = 0
                print("{}:".format(key))

            balance = await cls._get_holder_balance(sol_client, holder.address)
            key_total_balance += balance
            total_balance += balance

            data = "  {}: status={}, tx={}, size={} bytes, balance={:.9f} SOLs".format(
                holder.address,
                holder.status.name,
                holder.neon_tx_hash,
                holder.size,
                balance / (10**9),
            )
            print(data)

        _print_key_balance(key, key_total_balance)
        print("total: {:.9f} SOLs".format(total_balance / (10**9)))

    @classmethod
    async def get_holder_list(
        cls,
        core_api_client: CoreApiClient,
        signer_key_list: Sequence[SolPubKey],
        cmd: ListCmd,
    ) -> Sequence[HolderAccountModel]:
        holder_list: list[HolderAccountModel] = list()
        for key in signer_key_list:
            for res_id in range(cmd.start_id, cmd.stop_id):
                op_info = OpHolderInfo.from_raw(key, res_id, cmd.seed)
                holder_list.append(await core_api_client.get_holder_account(op_info.address))
        return holder_list

    @classmethod
    async def print_holder(
        cls,
        core_api_client: CoreApiClient,
        sol_client: SolClient,
        cmd: InfoCmd,
    ) -> None:
        holder: HolderAccountModel = await core_api_client.get_holder_account(cmd.address)
        balance = await cls._get_holder_balance(sol_client, cmd.address)
        tx = None
        if holder.tx:
            tx = dict(
                fromAddress=holder.tx.from_address.to_string(),
                toAddress=holder.tx.to_address.to_string(),
                nonce=holder.tx.nonce,
                value=holder.tx.value,
                input=holder.tx.call_data.to_string(),
                gasLimit=holder.tx.gas_limit,
                gasPrice=holder.tx.gas_price,
                maxFeePerGas=holder.tx.max_fee_per_gas,
                maxPriorityFeePerGas=holder.tx.max_priority_fee_per_gas,
                chainId=holder.tx.chain_id,
            )

        obj = dict(
            address=holder.address.to_string(),
            owner=holder.owner.to_string(),
            status=holder.status.value,
            size=holder.size,
            balance=balance / (10**9),
            chainId=holder.chain_id,
            evmSteps=holder.evm_step_cnt,
            transactionHash=holder.neon_tx_hash.to_string(),
            transactionType=hex(holder.tx_type) if holder.tx_type is not None else None,
            transactionBody=tx,
            block=dict(
                slot=holder.block.slot,
                time=holder.block.timestamp,
            ),
            accountKeyList=[k.to_string() for k in holder.account_key_list],
        )
        print(json.dumps(obj, indent=2))

    @staticmethod
    async def _get_holder_balance(sol_client: SolClient, address: SolPubKey) -> int:
        acct = await sol_client.get_account(address, 1)
        return acct.balance

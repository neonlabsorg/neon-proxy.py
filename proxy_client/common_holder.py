import json
import logging
from dataclasses import dataclass
from typing import Sequence

from common.config.legacy_holders import LEGACY_HOLDERS_ACCOUNTS as LHA
from common.neon_rpc.api import HolderAccountStatus, HolderAccountModel
from common.neon_rpc.client import CoreApiClient
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from proxy.operator_resource.key_info import OpHolderInfo
from proxy.base.op_client import OpResourceClient

_LOG = logging.getLogger(__name__)

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
        sol_client: SolClient,
        holder_list: Sequence[HolderAccountModel],
    ) -> None:
        def _print_signer_balance(_signer: SolPubKey, _holdcount: int, _balance: int) -> None:
            if _signer.is_empty:
                return
            print("total {}: {} holder accounts with {:.9f} SOLs".format(
                _signer, _holdcount, _balance / (10 ** 9)))
            print()

        total_balance = 0
        total_hlcount = 0
        total_sgcount = 0
        signer_balance = 0
        signer_hlcount = 0
        signer = SolPubKey.default()
        for holder in holder_list:
            if holder.owner.is_empty:
                continue

            if holder.owner != signer:
                _print_signer_balance(signer, signer_hlcount, signer_balance)
                #
                signer = holder.owner
                signer_balance = 0
                signer_hlcount = 0
                total_sgcount += 1
                print("{}:".format(signer))

            balance = await cls._get_holder_balance(sol_client, holder.address)
            signer_hlcount += 1
            signer_balance += balance
            total_hlcount += 1
            total_balance += balance

            data = "  {}: status={}, tx={}, size={} bytes, balance={:.9f} SOLs".format(
                holder.address,
                holder.status.name,
                holder.neon_tx_hash,
                holder.size,
                balance / (10**9),
            )
            print(data)

        _print_signer_balance(signer, signer_hlcount, signer_balance)
        print("total: {} operator keys with {} holder accounts and {:.9f} SOLs".format(
            total_sgcount, total_hlcount, total_balance / (10**9)))

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
    async def get_legacy_holder_list(
        cls,
        core_api_client: CoreApiClient,
        signer_key_list: Sequence[SolPubKey],
    ) -> Sequence[HolderAccountModel]:
        holder_list: list[HolderAccountModel] = list()
        for key in signer_key_list:
            if key in list(LHA.keys()):
                # collect holder accounts with status 51 (Holder Deprecated), 31 (Finalized Deprecated)
                holder_pubkeys = LHA[str(key)].get("51", []) + LHA[str(key)].get("31", [])
                for holder_pubkey in holder_pubkeys:
                    holder_addr = SolPubKey.from_raw(holder_pubkey)
                    holder_list.append(await core_api_client.get_holder_account(holder_addr))
        return holder_list

    @classmethod
    async def destroy_holder(
        cls,
        core_api_client: CoreApiClient,
        signer_key_list: Sequence[SolPubKey],
        op_client: OpResourceClient,
        req_id: dict,
        holder: HolderAccountModel
    ) -> bool:
        if holder.status == HolderAccountStatus.Empty:
            _LOG.error("holder %s doesn't exist", holder.address)
            return False
        if holder.owner not in signer_key_list:
            _LOG.error("unknown Holder owner %s", holder.owner)
            return False
        await op_client.destroy_holder(req_id, holder.owner, holder.address)
        return True

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
            accountKeyList=[k.to_string() for k in holder.account_key_list],
        )
        print(json.dumps(obj, indent=2))

    @staticmethod
    async def _get_holder_balance(sol_client: SolClient, address: SolPubKey) -> int:
        acct = await sol_client.get_account(address, 1)
        return acct.balance

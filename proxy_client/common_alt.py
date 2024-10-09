import json

from common.solana.account import SolAccountModel
from common.solana.alt_program import SolAltProg, SolAltAccountInfo
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from proxy.base.op_client import OpResourceClient


class SolAltFunc:
    async def print_alt_list(self, req_id: dict, owner: str, op_client: OpResourceClient, sol_client: SolClient) -> None:
        if owner.upper() == "ALL":
            await self._print_all_alt(req_id, op_client, sol_client)
        else:
            owner = SolPubKey.from_raw(owner)
            balance = await self._print_alt_by_owner(sol_client, owner, False)
            print("total: {:.9f} SOLs".format(balance / (10 ** 9)))

    async def _print_all_alt(self, req_id: dict, op_client: OpResourceClient, sol_client: SolClient) -> None:
        owner_list = await op_client.get_signer_key_list(req_id)
        total_balance = 0
        for owner in owner_list:
            balance = await self._print_alt_by_owner(sol_client, owner, True)
            total_balance += balance
        print("total: {:.9f} SOLs".format(total_balance / (10 ** 9)))

    @classmethod
    async def _print_alt_by_owner(cls, sol_client: SolClient, owner: SolPubKey, print_owner: bool) -> int:
        acct_list = await cls.get_alt_list(sol_client, owner)

        total_balance = 0
        for acct in acct_list:
            alt = SolAltAccountInfo.from_bytes(acct.address, acct.data)
            status = "deactivated" if alt.is_deactivated else "active"
            total_balance += acct.balance
            data = "{}\t{}\t{:.9f} SOLs".format(acct.address, status, acct.balance / (10 ** 9))
            if print_owner:
                data = f"{owner}:\t{data}"
            print(data)
        return total_balance

    @classmethod
    async def print_alt(cls, sol_client: SolClient, address: SolPubKey) -> None:
        acct = await sol_client.get_account(address)
        alt = SolAltAccountInfo.from_bytes(address, acct.data)
        obj = dict(
            address=address.to_string(),
            size=len(acct.data),
            balance=(acct.balance / (10 ** 9)),
            owner=alt.owner.to_string(),
            isExist=alt.is_exist,
            isDeactivated=alt.is_deactivated,
            lastExtendedSlot=alt.last_extended_slot,
            deactivationSlot=alt.deactivation_slot,
            accountKeyList=[k.to_string() for k in alt.account_key_list],
        )
        print(json.dumps(obj, indent=2))

    @staticmethod
    async def get_alt_list(sol_client: SolClient, owner: SolPubKey) -> tuple[SolAccountModel, ...]:
        return await sol_client.get_prog_account_list(
            prg_key=SolAltProg.ID,
            offset=0,
            size=SolAltAccountInfo.MetaSize,
            filter_offset=SolAltAccountInfo.OwnerOffset,
            filter_data=owner.to_bytes(),
            commit=SolCommit.Confirmed,
        )

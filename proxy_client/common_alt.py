from common.solana.account import SolAccountModel
from common.solana.alt_program import SolAltProg, SolAltAccountInfo
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from proxy.base.op_client import OpResourceClient


class SolAltFunc:
    async def print_alt(self, req_id: dict, owner: str, op_client: OpResourceClient, sol_client: SolClient) -> None:
        if owner.upper() == "ALL":
            await self._print_all_alt(req_id, op_client, sol_client)
        else:
            owner = SolPubKey.from_raw(owner)
            await self._print_alt_by_owner(sol_client, owner, False)

    async def _print_all_alt(self, req_id: dict, op_client: OpResourceClient, sol_client: SolClient) -> None:
        owner_list = await op_client.get_signer_key_list(req_id)
        for owner in owner_list:
            await self._print_alt_by_owner(sol_client, owner, True)

    @classmethod
    async def _print_alt_by_owner(cls, sol_client: SolClient, owner: SolPubKey, print_owner: bool) -> None:
        acct_list = await cls._get_alt_list(sol_client, owner)

        for acct in acct_list:
            alt = SolAltAccountInfo.from_bytes(acct.address, acct.data)
            status = "deactivated" if alt.is_deactivated else "active"
            data = f"{acct.address}\t{status}\t{acct.lamports}"
            if print_owner:
                data = f"{owner}:\t{data}"
            print(data)

    @staticmethod
    async def _get_alt_list(sol_client: SolClient, owner: SolPubKey) -> tuple[SolAccountModel, ...]:
        return await sol_client.get_prog_account_list(
            prg_key=SolAltProg.ID,
            offset=0,
            size=SolAltAccountInfo.MetaSize,
            filter_offset=SolAltAccountInfo.OwnerOffset,
            filter_data=owner.to_bytes(),
            commit=SolCommit.Confirmed,
        )

from common.solana.alt_program import SolAltProg, SolAltAccountInfo
from common.solana.commit_level import SolCommit
from common.solana.pubkey import SolPubKey
from common.solana_rpc.client import SolClient
from proxy.base.op_client import OpResourceClient


class SolAltFunc:
    async def print_all_alt(self, req_id: dict, op_client: OpResourceClient, sol_client: SolClient) -> None:
        owner_list = await op_client.get_signer_key_list(req_id)
        for owner in owner_list:
            await self.print_alt_by_owner(sol_client, owner, True)

    @staticmethod
    async def print_alt_by_owner(sol_client: SolClient, owner: SolPubKey, print_owner: bool) -> None:
        acct_list = await sol_client.get_prg_account_list(
            prg_key=SolAltProg.ID,
            offset=0,
            size=SolAltAccountInfo.MetaSize,
            filter_offset=SolAltAccountInfo.AuthOffset,
            filter_data=owner.to_bytes(),
            commit=SolCommit.Confirmed,
        )

        for acct in acct_list:
            data = f"{acct.address}\t{acct.lamports}"
            if print_owner:
                data = f"{owner}:\t{data}"
            print(data)

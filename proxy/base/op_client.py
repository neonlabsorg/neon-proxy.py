from __future__ import annotations

from typing import Sequence

from common.app_data.client import AppDataClient
from common.ethereum.bin_str import EthBinStrField
from common.ethereum.hash import EthAddressField
from common.neon.transaction_model import NeonTxModel
from common.solana.pubkey import SolPubKey
from common.solana.transaction import SolTx
from common.solana.transaction_model import SolTxModel
from .op_api import (
    OP_RESOURCE_ENDPOINT,
    OpResourceModel,
    OpGetResourceRequest,
    OpFreeResourceRequest,
    OpResourceResp,
    OpTokenSolAddressModel,
    OpGetTokenSolAddressRequest,
    OpSignEthMsgRequest,
    OpSignEthMsgResp,
    OpSignEthTxRequest,
    OpSignEthTxResp,
    OpSignSolTxListRequest,
    OpSolTxListResp,
    OpGetSignerKeyListRequest,
    OpSignerKeyListResp,
    OpWithdrawTokenRequest,
    OpWithdrawTokenResp,
    OpGetEthAddressListRequest,
    OpEthAddressListResp,
    OpEthAddressModel,
)


class OpResourceClient(AppDataClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect(
            host=self._cfg.op_resource_ip,
            port=self._cfg.op_resource_port,
            path=OP_RESOURCE_ENDPOINT,
        )

    async def get_resource(self, req_id: dict, chain_id: int | None) -> OpResourceModel:
        return await self._get_resource(OpGetResourceRequest(req_id=req_id, chain_id=chain_id))

    async def free_resource(self, req_id: dict, is_good_resource: bool, resource: OpResourceModel) -> bool:
        req = OpFreeResourceRequest(req_id=req_id, is_good=is_good_resource, resource=resource)
        resp = await self._free_resource(req)
        return resp.result

    async def get_token_sol_address(self, req_id: dict, owner: SolPubKey, chain_id: int) -> SolPubKey:
        req = OpGetTokenSolAddressRequest(req_id=req_id, owner=owner, chain_id=chain_id)
        resp = await self._get_token_sol_address(req)
        return resp.token_sol_address

    async def sign_eth_msg(self, req_id: dict, sender: EthAddressField, data: EthBinStrField) -> OpSignEthMsgResp:
        req = OpSignEthMsgRequest(req_id=req_id, sender=sender, data=data)
        return await self._sign_eth_msg(req)

    async def sign_eth_tx(self, req_id: dict, neon_tx: NeonTxModel, chain_id: int) -> OpSignEthTxResp:
        req = OpSignEthTxRequest(req_id=req_id, neon_tx=neon_tx, chain_id=chain_id)
        return await self._sign_eth_tx(req)

    async def sign_sol_tx_list(self, req_id: dict, owner: SolPubKey, tx_list: Sequence[SolTx]) -> tuple[SolTx, ...]:
        model_list = [SolTxModel.from_raw(tx) for tx in tx_list]
        req = OpSignSolTxListRequest(req_id=req_id, owner=owner, tx_list=model_list)
        resp = await self._sign_sol_tx_list(req)
        return tuple([model.tx for model in resp.tx_list])

    async def get_signer_key_list(self, req_id: dict) -> tuple[SolPubKey, ...]:
        req = OpGetSignerKeyListRequest(req_id=req_id)
        resp = await self._get_signer_key_list(req)
        return tuple(resp.signer_key_list)

    async def get_eth_address_list(self, req_id: dict) -> tuple[OpEthAddressModel, ...]:
        req = OpGetEthAddressListRequest(req_id=req_id)
        resp = await self._get_eth_list(req)
        return tuple(resp.eth_address_list)

    async def withdraw(self, req_id: dict, chain_list: list[int]) -> None:
        req = OpWithdrawTokenRequest(req_id=req_id, chain_list=chain_list)
        _resp = await self._withdraw(req)

    @AppDataClient.method(name="getOperatorResource")
    async def _get_resource(self, request: OpGetResourceRequest) -> OpResourceModel: ...

    @AppDataClient.method(name="freeOperatorResource")
    async def _free_resource(self, request: OpFreeResourceRequest) -> OpResourceResp: ...

    @AppDataClient.method(name="getOperatorTokenAddress")
    async def _get_token_sol_address(self, request: OpGetTokenSolAddressRequest) -> OpTokenSolAddressModel: ...

    @AppDataClient.method(name="signEthMessage")
    async def _sign_eth_msg(self, request: OpSignEthMsgRequest) -> OpSignEthMsgResp: ...

    @AppDataClient.method(name="signEthTransaction")
    async def _sign_eth_tx(self, request: OpSignEthTxRequest) -> OpSignEthTxResp: ...

    @AppDataClient.method(name="signSolanaTransactionList")
    async def _sign_sol_tx_list(self, request: OpSignSolTxListRequest) -> OpSolTxListResp: ...

    @AppDataClient.method(name="getSignerKeyList")
    async def _get_signer_key_list(self, request: OpGetSignerKeyListRequest) -> OpSignerKeyListResp: ...

    @AppDataClient.method(name="getEthAddressList")
    async def _get_eth_list(self, request: OpGetEthAddressListRequest) -> OpEthAddressListResp: ...

    @AppDataClient.method(name="withdrawEarnedTokens")
    async def _withdraw(self, request: OpWithdrawTokenRequest) -> OpWithdrawTokenResp: ...

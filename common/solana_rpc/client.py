from __future__ import annotations

import asyncio
import itertools
import logging
import typing as tp
from dataclasses import dataclass
from typing import TypeVar, Sequence, Union, Final

import solders.account_decoder as _acct
import solders.rpc.config as _cfg
import solders.rpc.errors as _err
import solders.rpc.filter as _filter
import solders.rpc.requests as _req
import solders.rpc.responses as _resp
import solders.transaction_status as _tx

from .errors import SolRpcError
from ..config.config import Config
from ..http.client import HttpClient, HttpClientRequest
from ..http.utils import HttpURL
from ..jsonrpc.errors import InternalJsonRpcError
from ..solana.account import SolAccountModel
from ..solana.alt_program import SolAltAccountInfo
from ..solana.block import SolRpcBlockInfo
from ..solana.commit_level import SolCommit
from ..solana.hash import SolBlockHash
from ..solana.pubkey import SolPubKey
from ..solana.signature import SolTxSig, SolRpcTxSigInfo
from ..solana.transaction import SolTx
from ..solana.transaction_meta import (
    SolRpcTxSlotInfo,
    SolRpcErrorInfo,
    SolRpcExtErrorInfo,
    SolRpcTxFieldErrorCode,
    SolRpcSendTxErrorInfo,
    SolRpcNodeUnhealthyErrorInfo,
    SolRpcInvalidParamErrorInfo,
)
from ..stat.client_rpc import RpcStatClient, RpcClientRequest
from ..utils.cached import ttl_cached_method

_SolRpcResp = TypeVar("_SolRpcResp", bound=_resp.RPCResult)

_SoldersAcctInfoCfg = _cfg.RpcAccountInfoConfig
_SoldersAcctEnc = _acct.UiAccountEncoding
_SoldersDataSliceCfg = _acct.UiDataSliceConfig

_SoldersRpcCtxCfg = _cfg.RpcContextConfig
_SoldersBlockCfg = _cfg.RpcBlockConfig

_SoldersTxSigCfg = _cfg.RpcSignaturesForAddressConfig

_SoldersTxCfg = _cfg.RpcTransactionConfig
_SoldersTxEnc = _tx.UiTransactionEncoding
_SoldersTxDet = _tx.TransactionDetails

_SoldersPrgAcctCfg = _cfg.RpcProgramAccountsConfig
_SoldersFilterMemcmp = _filter.Memcmp

_SoldersRpcReq = _req.Body
_SoldersGetVer = _req.GetVersion
_SoldersGetBalance = _req.GetBalance
_SoldersGetAcctInfo = _req.GetAccountInfo
_SoldersGetAcctInfoList = _req.GetMultipleAccounts
_SoldersGetSlotList = _req.GetBlocks
_SoldersGetFirstSlot = _req.GetFirstAvailableBlock
_SoldersGetSlot = _req.GetSlot
_SoldersGetBlock = _req.GetBlock
_SoldersGetBlockCommit = _req.GetBlockCommitment
_SoldersGetLatestBlockhash = _req.GetLatestBlockhash
_SoldersGetBlockHeight = _req.GetBlockHeight
_SoldersGetTxSigForAddr = _req.GetSignaturesForAddress
_SoldersGetTx = _req.GetTransaction
_SoldersGetRentBalance = _req.GetMinimumBalanceForRentExemption
_SoldersGetHealth = _req.GetHealth
_SoldersGetNodeList = _req.GetClusterNodes
_SoldersGetPrgAcctList = _req.GetProgramAccounts

_SoldersGetVerResp = _resp.GetVersionResp
_SoldersGetBalanceResp = _resp.GetBalanceResp
_SoldersGetAcctInfoResp = _resp.GetAccountInfoResp
_SoldersGetAcctInfoListResp = _resp.GetMultipleAccountsResp
_SoldersGetSlotListResp = _resp.GetBlocksResp
_SoldersGetFirstSlotResp = _resp.GetFirstAvailableBlockResp
_SoldersGetSlotResp = _resp.GetSlotResp
_SoldersGetBlockResp = _resp.GetBlockResp
_SoldersGetBlockCommitResp = _resp.GetBlockCommitmentResp
_SoldersGetLatestBlockhashResp = _resp.GetLatestBlockhashResp
_SoldersGetBlockHeightResp = _resp.GetBlockHeightResp
_SoldersGetTxSigForAddrResp = _resp.GetSignaturesForAddressResp
_SoldersGetTxResp = _resp.GetTransactionResp
_SoldersGetRentBalanceResp = _resp.GetMinimumBalanceForRentExemptionResp
_SoldersGetHealthResp = _resp.GetHealthResp
_SoldersGetNodeListResp = _resp.GetClusterNodesResp
_SoldersGetPrgAcctListResp = _resp.GetProgramAccountsResp

_SoldersSendTxCfg = _cfg.RpcSendTransactionConfig
_SoldersSendTx = _req.SendRawTransaction
_SoldersSendTxResp = _resp.SendTransactionResp
_SoldersPreflightError = _err.SendTransactionPreflightFailureMessage
_SoldersNodeUnhealthyError = _err.NodeUnhealthyMessage

_LOG = logging.getLogger(__name__)

SolRpcSendTxResultInfo = Union[
    SolTxSig,
    SolRpcSendTxErrorInfo,
    SolRpcNodeUnhealthyErrorInfo,
    SolRpcInvalidParamErrorInfo,
]

SolRpcContactInfo = _resp.RpcContactInfo


@dataclass(frozen=True)
class SolBlockStatus:
    slot: int
    commit: SolCommit

    @staticmethod
    def new_empty(slot: int) -> SolBlockStatus:
        return SolBlockStatus(slot=slot, commit=SolCommit.Processed)


class SolClient(HttpClient):
    _stat_name: Final[str] = "Solana"

    def __init__(self, cfg: Config, stat_client: RpcStatClient) -> None:
        super().__init__(cfg)
        self.set_timeout_sec(cfg.sol_timeout_sec)

        self._stat_client = stat_client
        self._id = itertools.count()

        url_list = tuple([HttpURL(url) for url in self._cfg.sol_url_list])
        self.connect(base_url_list=url_list)

        self._send_tx_url_list = tuple([HttpURL(url) for url in self._cfg.sol_send_tx_url_list])
        for url in self._send_tx_url_list:
            assert url.is_absolute(), "Solana URL for send transaction must be absolute"

    def _get_next_id(self) -> int:
        return next(self._id)

    async def _send_request(
        self,
        request: _SoldersRpcReq,
        parser: type[_SolRpcResp],
        *,
        base_url_list: Sequence[HttpURL] = tuple(),
    ) -> _SolRpcResp:
        request = RpcClientRequest.from_raw(
            data=request.to_json(),
            stat_client=self._stat_client,
            stat_name=self._stat_name,
            method=request.__class__.__name__[:1].lower() + request.__class__.__name__[1:]
        )

        with request:
            for retry in itertools.count():
                request.start_timer()
                resp_json = await self._send_client_request(request, base_url_list=base_url_list)
                try:

                    resp = parser.from_json(resp_json)
                    if isinstance(resp, tp.get_args(SolRpcExtErrorInfo)):
                        raise SolRpcError(resp)

                except BaseException as exc:
                    if retry > self._max_retry_cnt:
                        if isinstance(exc, SolRpcError):
                            raise exc
                        raise InternalJsonRpcError(exc)

                    _LOG.warning("bad Solana response '%s' on the request '%s'", resp_json, request.data)
                    request.commit_stat(is_error=True)
                    await asyncio.sleep(0.2)
                    continue

                if isinstance(resp, tp.get_args(SolRpcErrorInfo)):
                    raise SolRpcError(resp)

                return resp

    def _exception_handler(self, url: HttpURL, request: HttpClientRequest, retry: int, exc: BaseException) -> None:
        super()._exception_handler(url, request, retry, exc)

        # if the previous call has reraised an exception, this code isn't called
        assert isinstance(request, RpcClientRequest)
        request.commit_stat(is_error=True)

    @ttl_cached_method(ttl_sec=60)
    async def get_version(self) -> str:
        req = _SoldersGetVer(self._get_next_id())
        resp = await self._send_request(req, _SoldersGetVerResp)
        return "Solana/v" + resp.value.solana_core

    async def get_balance(self, address: SolPubKey, commit=SolCommit.Confirmed) -> int:
        cfg = _SoldersRpcCtxCfg(commit.to_rpc_commit(), None)
        req = _SoldersGetBalance(address, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetBalanceResp)
        return resp.value

    async def get_account(
        self,
        address: SolPubKey,
        size: int | None = None,
        commit=SolCommit.Confirmed,
    ) -> SolAccountModel:
        data_slice = None if not size else _SoldersDataSliceCfg(0, size)
        cfg = _SoldersAcctInfoCfg(
            _SoldersAcctEnc.Base64,
            data_slice=data_slice,
            commitment=commit.to_rpc_commit(),
        )
        req = _SoldersGetAcctInfo(address, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetAcctInfoResp)
        return SolAccountModel.from_raw(address, resp.value)

    async def get_alt_account(self, address: SolPubKey, commit=SolCommit.Confirmed) -> SolAltAccountInfo:
        acct = await self.get_account(address, commit=commit)
        return SolAltAccountInfo.from_bytes(address, acct.data)

    async def get_account_list(
        self,
        address_list: Sequence[SolPubKey],
        size: int | None = None,
        commit=SolCommit.Confirmed,
    ) -> tuple[SolAccountModel, ...]:
        data_slice = None if not size else _SoldersDataSliceCfg(0, size)
        cfg = _SoldersAcctInfoCfg(
            _SoldersAcctEnc.Base64,
            data_slice=data_slice,
            commitment=commit.to_rpc_commit(),
        )
        req = _SoldersGetAcctInfoList(address_list, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetAcctInfoListResp)
        return tuple([SolAccountModel.from_raw(addr, raw) for addr, raw in zip(address_list, resp.value)])

    async def get_slot_list(self, start_slot: int, stop_slot, commit=SolCommit.Confirmed) -> tuple[int, ...]:
        req = _SoldersGetSlotList(start_slot, stop_slot, commit.to_rpc_commit(), self._get_next_id())
        resp = await self._send_request(req, _SoldersGetSlotListResp)
        return tuple(resp.value)

    async def get_slot(self, commit=SolCommit.Confirmed) -> int:
        cfg = _SoldersRpcCtxCfg(commitment=commit.to_rpc_commit())
        req = _SoldersGetSlot(cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetSlotResp)
        return resp.value

    async def get_first_slot(self) -> int:
        req = _SoldersGetFirstSlot(self._get_next_id())
        resp = await self._send_request(req, _SoldersGetFirstSlotResp)
        _LOG.debug("first available slot: %s", resp.value)
        return resp.value

    async def get_block(self, slot: int, commit=SolCommit.Confirmed) -> SolRpcBlockInfo:
        cfg = _SoldersBlockCfg(
            _SoldersTxEnc.Base64,
            transaction_details=_SoldersTxDet.Full,
            rewards=False,
            commitment=commit.to_rpc_commit(),
            max_supported_transaction_version=0,
        )
        req = _SoldersGetBlock(slot, cfg, self._get_next_id())
        try:
            resp = await self._send_request(req, _SoldersGetBlockResp)
            if resp.value:
                if SolBlockHash.from_raw(resp.value.previous_blockhash).is_empty:
                    _LOG.debug("error on get block %s: empty parentBlockhash", slot)
                    return SolRpcBlockInfo.new_empty(slot, commit=commit)
        except SolRpcError as exc:
            _LOG.debug("error on get block %s: %s", slot, exc.message, extra=self._msg_filter)
            return SolRpcBlockInfo.new_empty(slot, commit=commit)
        return SolRpcBlockInfo.from_raw(resp.value, slot=slot, commit=commit)

    async def get_blockhash(self, slot: int) -> SolBlockHash:
        block = await self.get_block(slot)
        return block.block_hash

    async def get_block_status(self, slot: int) -> SolBlockStatus:
        finalized_block = await self.get_block(slot, SolCommit.Finalized)
        if not finalized_block.is_empty:
            return SolBlockStatus(slot, SolCommit.Finalized)

        req = _SoldersGetBlockCommit(slot, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetBlockCommitResp)

        voted_stake = sum(resp.value.commitment or [0])
        total_stake = resp.value.total_stake
        if (voted_stake * 100 / total_stake) > 66.6667:
            return SolBlockStatus(slot, SolCommit.Safe)

        return SolBlockStatus(slot, SolCommit.Confirmed)

    async def _get_latest_blockhash(self, commit=SolCommit.Confirmed) -> _SoldersGetLatestBlockhashResp:
        cfg = _SoldersRpcCtxCfg(commitment=commit.to_rpc_commit())
        req = _SoldersGetLatestBlockhash(cfg, self._get_next_id())
        return await self._send_request(req, _SoldersGetLatestBlockhashResp)

    async def get_recent_slot(self, commit=SolCommit.Confirmed) -> int:
        resp = await self._get_latest_blockhash(commit)
        return resp.context.slot

    async def get_recent_blockhash(self, commit=SolCommit.Confirmed) -> tuple[SolBlockHash, int]:
        resp = await self._get_latest_blockhash(commit)
        return SolBlockHash.from_raw(resp.value.blockhash), resp.value.last_valid_block_height

    async def get_block_height(self, commit=SolCommit.Confirmed) -> int:
        cfg = _SoldersRpcCtxCfg(commitment=commit.to_rpc_commit())
        resp = await self._send_request(_SoldersGetBlockHeight(cfg, self._get_next_id()), _SoldersGetBlockHeightResp)
        return resp.value

    async def get_tx_sig_list(
        self,
        address: SolPubKey,
        limit: int,
        commit=SolCommit.Confirmed,
    ) -> tuple[SolRpcTxSigInfo, ...]:
        cfg = _SoldersTxSigCfg(limit=limit, commitment=commit.to_rpc_commit())
        req = _SoldersGetTxSigForAddr(address, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetTxSigForAddrResp)
        return tuple(resp.value)

    async def get_tx(self, tx_sig: SolTxSig, commit=SolCommit.Confirmed, json_format=False) -> SolRpcTxSlotInfo | None:
        cfg = _SoldersTxCfg(
            _SoldersTxEnc.JsonParsed if json_format else _SoldersTxEnc.Base64,
            commitment=commit.to_rpc_commit(),
            max_supported_transaction_version=0,
        )
        req = _SoldersGetTx(tx_sig, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetTxResp)
        return resp.value

    async def get_tx_list(
        self,
        tx_sig_list: Sequence[SolTxSig],
        commit=SolCommit.Confirmed,
        json_format=False,
    ) -> tuple[SolRpcTxSlotInfo | None, ...]:
        if not tx_sig_list:
            return tuple()
        tx_list = await asyncio.gather(*[self.get_tx(tx_sig, commit, json_format) for tx_sig in tx_sig_list])
        return tuple(tx_list)

    async def send_tx(
        self,
        tx: SolTx,
        skip_preflight: bool,
        max_retry_cnt: int | None,
    ) -> SolRpcSendTxResultInfo | None:
        cfg = _SoldersSendTxCfg(
            skip_preflight=skip_preflight,
            preflight_commitment=SolCommit.Processed.to_rpc_commit(),
            max_retries=max_retry_cnt,
        )
        req = _SoldersSendTx(tx.serialize(), cfg, self._get_next_id())
        try:
            resp = await self._send_request(req, _SoldersSendTxResp, base_url_list=self._send_tx_url_list)
            return SolTxSig.from_raw(resp.value)
        except SolRpcError as exc:
            if isinstance(exc.rpc_data, _SoldersNodeUnhealthyError):
                return exc.rpc_data.data
            elif isinstance(exc.rpc_data, SolRpcInvalidParamErrorInfo):
                return exc.rpc_data
            elif isinstance(exc.rpc_data, _SoldersPreflightError):
                if exc.rpc_data.data.err == SolRpcTxFieldErrorCode.AlreadyProcessed:
                    return tx.sig
                return exc.rpc_data.data
            raise

    async def send_tx_list(
        self,
        tx_list: Sequence[SolTx],
        skip_preflight: bool,
        max_retry_cnt: int | None,
    ) -> tuple[SolRpcSendTxResultInfo | None, ...]:
        if not tx_list:
            return tuple()
        tx_sig_list = await asyncio.gather(*[self.send_tx(tx, skip_preflight, max_retry_cnt) for tx in tx_list])
        return tuple(tx_sig_list)

    async def get_rent_balance_for_size(self, size: int, commit=SolCommit.Confirmed) -> int:
        req = _SoldersGetRentBalance(size, commit.to_rpc_commit(), self._get_next_id())
        resp = await self._send_request(req, _SoldersGetRentBalanceResp)
        return resp.value

    async def get_health(self) -> int | None:
        _big_value: Final[int] = 4096  # some big value

        req = _SoldersGetHealth(self._get_next_id())
        try:
            resp = await self._send_request(req, _SoldersGetHealthResp)
            if resp.value == "ok":
                return None

            _LOG.warning("unexpected response on get health: %s", resp.value)
            return _big_value

        except SolRpcError as exc:
            if isinstance(exc.rpc_data, _SoldersNodeUnhealthyError):
                return exc.rpc_data.data.num_slots_behind

            _LOG.warning("unexpected error on get health", exc_info=exc, extra=self._msg_filter)
            return _big_value

    async def get_sol_node_list(self) -> list[SolRpcContactInfo]:
        req = _SoldersGetNodeList(self._get_next_id())
        resp = await self._send_request(req, _SoldersGetNodeListResp)
        return resp.value

    async def get_prog_account_list(
        self,
        prg_key: SolPubKey,
        offset: int,
        size: int,
        filter_offset: int,
        filter_data: bytes,
        commit: SolCommit = SolCommit.Confirmed,
    ) -> tuple[SolAccountModel, ...]:
        data_slice = _SoldersDataSliceCfg(offset, size)
        acct_cfg = _SoldersAcctInfoCfg(
            _SoldersAcctEnc.Base64,
            data_slice=data_slice,
            commitment=commit.to_rpc_commit(),
        )
        flt = _SoldersFilterMemcmp(
            offset=filter_offset,
            bytes_=filter_data,
        )
        cfg = _SoldersPrgAcctCfg(acct_cfg, [flt])

        req = _SoldersGetPrgAcctList(prg_key, cfg, self._get_next_id())
        resp = await self._send_request(req, _SoldersGetPrgAcctListResp)
        return tuple([SolAccountModel.from_raw(SolPubKey.from_raw(acct.pubkey), acct.account) for acct in resp.value])

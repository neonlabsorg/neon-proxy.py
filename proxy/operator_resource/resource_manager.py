from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from typing import Sequence, Final

from common.config.constants import ONE_BLOCK_SEC
from common.ethereum.hash import EthAddress
from common.neon.account import NeonAccount
from common.neon.neon_program import NeonProg
from common.neon_rpc.api import EvmConfigModel, HolderAccountStatus, NeonAccountStatus
from common.solana.instruction import SolTxIx
from common.solana.pubkey import SolPubKey
from common.solana.signer import SolSigner
from common.solana.sys_program import SolSysProg
from common.solana.transaction import SolTx
from common.solana.transaction_legacy import SolLegacyTx
from common.solana_rpc.transaction_list_sender import SolTxListSender
from common.solana_rpc.ws_client import SolWatchTxSession
from common.utils.cached import cached_property, reset_cached_method
from common.utils.json_logger import log_msg, logging_context
from .key_info import OpSignerInfo, OpHolderInfo
from .server_abc import OpResourceComponent
from .transaction_list_signer import OpTxListSigner
from ..base.op_api import OpResourceModel

_LOG = logging.getLogger(__name__)


class OpResourceMng(OpResourceComponent):
    _activate_sleep_sec: Final[float] = ONE_BLOCK_SEC * 16
    _show_error_period: Final[int] = 5 * 60 // _activate_sleep_sec  # each 5 minutes
    _show_warn_period: Final[int] = 1 * 60 // _activate_sleep_sec  # ~ each 1 minutes

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # active resources
        self._active_signer_dict: dict[SolPubKey, OpSignerInfo] = dict()
        # resources for activating
        self._disabled_signer_dict: dict[SolPubKey, OpSignerInfo] = dict()
        # resources for removing
        self._deactivated_signer_dict: dict[SolPubKey, OpSignerInfo] = dict()

        # resources blocked by external call from proxy-cli
        self._blocked_holder_addr_dict: dict[SolPubKey, SolPubKey] = dict()
        # dropped resources
        self._deleted_holder_addr_set: set[SolPubKey] = set()

        self._holder_size = 0
        self._holder_balance = 0
        self._last_signer_idx = 0

        self._stop_event = asyncio.Event()
        self._refresh_signer_task: asyncio.Task | None = None
        self._activate_signer_task: asyncio.Task | None = None

    @cached_property
    def _sol_watch_tx_session(self) -> SolWatchTxSession:
        return SolWatchTxSession(self._cfg, self._sol_client)

    async def start(self) -> None:
        self._refresh_signer_task = asyncio.create_task(self._refresh_signer_loop())
        self._activate_signer_task = asyncio.create_task(self._activate_signer_loop())
        self._holder_size = self._cfg.holder_size
        self._holder_balance = await self._sol_client.get_rent_balance_for_size(self._holder_size)

    async def stop(self) -> None:
        self._stop_event.set()
        if self._refresh_signer_task:
            await self._refresh_signer_task
        if self._activate_signer_task:
            await self._activate_signer_task

    def get_resource(self, chain_id: int | None) -> OpResourceModel:
        if not (op_signer_list := list(self._active_signer_dict.values())):
            return OpResourceModel.default()

        len_op_signer_list = len(op_signer_list)
        for retry in range(len_op_signer_list):
            if self._last_signer_idx >= len_op_signer_list:
                self._last_signer_idx = 0

            op_signer = op_signer_list[self._last_signer_idx]
            self._last_signer_idx += 1
            if not op_signer.free_holder_list:
                continue

            with logging_context(opkey=self._opkey(op_signer)):
                owner_token_addr = op_signer.token_sol_address_dict.get(chain_id, SolPubKey.default())

                op_holder = op_signer.free_holder_list.popleft()
                op_signer.used_holder_dict[op_holder.address] = op_holder

                op_resource = OpResourceModel(
                    owner=op_signer.owner,
                    holder_address=op_holder.address,
                    resource_id=op_holder.resource_id,
                    eth_address=op_signer.eth_address,
                    token_sol_address=owner_token_addr,
                )

                _LOG.debug("got resource: %s", op_resource)
                return op_resource

        return OpResourceModel.default()

    def free_resource(self, is_good_resource: bool, op_resource: OpResourceModel) -> None:
        with logging_context(opkey=self._opkey(op_resource.owner)):
            if not (op_signer := self._find_op_signer(op_resource.owner)):
                _LOG.error("error on trying to free an absent resource %s", op_resource)
                return
            elif not (op_holder := op_signer.used_holder_dict.pop(op_resource.holder_address, None)):
                _LOG.error("error on trying to free a not-used resource %s", op_resource)
                return

            if is_good_resource:
                _LOG.debug("free resource: %s", op_resource)
                op_signer.free_holder_list.append(op_holder)
            else:
                _LOG.debug("disable resource: %s", op_resource)
                op_signer.disabled_holder_list.append(op_holder)

    def get_token_address(self, owner: SolPubKey, chain_id: int) -> tuple[EthAddress, SolPubKey]:
        with logging_context(opkey=self._opkey(owner)):
            if not (op_signer := self._find_op_signer(owner)):
                _LOG.error("error on trying to find owner of token address %s:%s", owner, chain_id)
                return EthAddress.default(), SolPubKey.default()

            token_sol_addr = op_signer.token_sol_address_dict.get(chain_id, SolPubKey.default())
            if token_sol_addr.is_empty:
                _LOG.error("error on trying to find token address %s for absent chain_id %s", owner, chain_id)
            else:
                _LOG.debug("got token_address %s for %s:%s", token_sol_addr, owner, hex(chain_id))
        return op_signer.eth_address, token_sol_addr

    async def sign_tx_list(self, payer: SolPubKey, tx_list: Sequence[SolTx]) -> tuple[SolTx, ...]:
        with logging_context(opkey=self._opkey(payer)):
            if not (op_signer := self._find_op_signer(payer)):
                _LOG.error("error on trying to find payer %s to sign the tx-list", payer)
                return tuple(tx_list)

            tx_signer = OpTxListSigner(signer=op_signer.signer)

            if not await self._validate_op_balance(op_signer):
                if op_signer := self._active_signer_dict.pop(op_signer.owner, None):
                    self._disabled_signer_dict[op_signer.owner] = op_signer

            tx_list = await tx_signer.sign_tx_list(tx_list)
            _LOG.debug("done sign the tx-list: %s", tx_list)
        return tx_list

    def get_signer_key_list(self) -> tuple[SolPubKey, ...]:
        return self._get_signer_key_list()

    def _find_op_signer(self, owner: SolPubKey) -> OpSignerInfo | None:
        if not (op_signer := self._active_signer_dict.get(owner, None)):
            if not (op_signer := self._deactivated_signer_dict.get(owner, None)):
                if not (op_signer := self._disabled_signer_dict.get(owner, None)):
                    _LOG.debug("error on trying to find signer %s", owner)
                    return None
        return op_signer

    async def _refresh_signer_loop(self) -> None:
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                sleep_sec = 5 * 60 if self._active_signer_dict else 5
                await asyncio.wait_for(self._stop_event.wait(), sleep_sec)
            if self._stop_event.is_set():
                break

            try:
                await self._refresh_signer_list()
            except BaseException as exc:
                _LOG.error("error on refresh secret list", exc_info=exc)

    async def _refresh_signer_list(self) -> None:
        signer_list = await self._server.get_signer_list()
        if len(signer_list) >= 64:
            _LOG.warning("secret list is too long, holder checking can be slow %s", len(signer_list))

        new_signer_list: list[SolSigner] = list()
        rm_act_signer_set = set(self._active_signer_dict.keys())
        rm_dis_signer_set = set(self._disabled_signer_dict.keys())

        for signer in signer_list:
            owner = signer.pubkey
            if owner in rm_act_signer_set:
                rm_act_signer_set.discard(owner)
            elif owner in rm_dis_signer_set:
                rm_dis_signer_set.discard(owner)
            elif op_signer := self._deactivated_signer_dict.pop(owner, None):
                self._disabled_signer_dict[owner] = op_signer
            else:
                new_signer_list.append(signer)

        self._deactivated_signer_dict.update({k: self._active_signer_dict.pop(k) for k in rm_act_signer_set})
        self._deactivated_signer_dict.update({k: self._disabled_signer_dict.pop(k) for k in rm_dis_signer_set})

        for signer in new_signer_list:
            op_signer = self._init_op_signer(signer)
            self._deleted_holder_addr_set.update([h.address for h in op_signer.disabled_holder_list])
            self._disabled_signer_dict[signer.pubkey] = op_signer

    def _init_op_signer(self, signer: SolSigner) -> OpSignerInfo:
        start_id = self._cfg.perm_account_id
        stop_id = self._cfg.perm_account_id + self._cfg.perm_account_limit

        return OpSignerInfo(
            signer=signer,
            eth_address=NeonAccount.from_private_key(signer.secret, 0).eth_address,
            token_sol_address_dict=dict(),
            free_holder_list=deque(),
            used_holder_dict=dict(),
            disabled_holder_list=deque([OpHolderInfo.from_raw(signer.pubkey, rid) for rid in range(start_id, stop_id)]),
        )

    async def _activate_signer_loop(self) -> None:
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), self._activate_sleep_sec)
            if self._stop_event.is_set():
                break

            try:
                await self._activate_signer_list()
                await self._delete_signer_list()
                await self._delete_blocked_holder_list()
            except BaseException as exc:
                _LOG.error("error on active operator keys", exc_info=exc)

    async def _activate_signer_list(self) -> None:
        op_signer_list = [s for s in self._active_signer_dict.values() if s.disabled_holder_list or s.warn_cnt]
        op_signer_list.extend(self._disabled_signer_dict.values())
        evm_cfg = await self._server.get_evm_cfg() if op_signer_list else None

        for op_signer in tuple(op_signer_list):
            with logging_context(opkey=self._opkey(op_signer)):
                if await self._activate_signer(op_signer, evm_cfg):
                    if op_signer := self._disabled_signer_dict.pop(op_signer.owner, None):
                        # move the key to the active list for using in tx processing
                        self._active_signer_dict[op_signer.owner] = op_signer

    @staticmethod
    def _opkey(owner: SolPubKey | OpSignerInfo) -> str:
        if isinstance(owner, OpSignerInfo):
            owner = owner.owner
        return owner.to_string()[:8]

    async def _activate_signer(self, op_signer: OpSignerInfo, evm_cfg: EvmConfigModel) -> bool:
        if not await self._validate_op_balance(op_signer):
            # if no enough tokens to create accounts and tx processing
            return False

        holder: OpHolderInfo | None = None
        holder_list, op_signer.disabled_holder_list = op_signer.disabled_holder_list, deque()
        try:
            while holder_list:
                holder = holder_list.popleft()
                if await self._validate_holder_acct(op_signer.signer, holder):
                    op_signer.free_holder_list.append(holder)
                else:
                    op_signer.disabled_holder_list.append(holder)
                holder = None
        except BaseException as exc:
            _LOG.error("error on validate holder account", exc_info=exc, extra=self._msg_filter)
            if holder:
                op_signer.disabled_holder_list.append(holder)
            op_signer.disabled_holder_list.extend(holder_list)
            return False

        if not op_signer.free_holder_list:
            _LOG.warning(log_msg("operator key {Owner} doesn't have active holders", Owner=op_signer.owner))
            return False
        elif not await self._validate_op_balance(op_signer):
            # if no enough tokens after creation of holder accounts
            return False

        if not await self._validate_neon_acct_list(op_signer, evm_cfg):
            # cannot create neon accounts for all chain-ids
            return False

        # validate that key still has enough tokens for tx processing
        return await self._validate_op_balance(op_signer)

    async def _validate_op_balance(self, op_signer: OpSignerInfo) -> bool:
        # Validate operator's account has enough SOLs
        balance = await self._sol_client.get_balance(op_signer.owner)
        if balance <= self._cfg.min_op_balance_to_err:
            if op_signer.error_cnt % self._show_error_period == 0:
                msg = log_msg(
                    "operator key {OpKeyAddress} has NOT enough SOLs; balance = {Balance}; "
                    "min_operator_balance_to_err = {MinBalance}",
                    OpAddress=op_signer.owner,
                    Balance=balance,
                    MinBalance=self._cfg.min_op_balance_to_err,
                )
                _LOG.error(msg)
            op_signer.error_cnt += 1
            return False
        else:
            op_signer.error_cnt = 0

        if balance <= self._cfg.min_op_balance_to_warn:
            if op_signer.warn_cnt % self._show_error_period == 0:
                msg = log_msg(
                    "operator account {OpKeyAddress} SOLs are running out; balance = {Balance}; "
                    "min_operator_balance_to_warn = {MinBalance}",
                    OpAddress=op_signer.owner,
                    Balance=balance,
                    MinBalance=self._cfg.min_op_balance_to_warn,
                )
                _LOG.warning(msg)
            op_signer.warn_cnt += 1
        else:
            op_signer.warn_cnt = 0

        return True

    async def _validate_holder_acct(self, signer: SolSigner, op_holder: OpHolderInfo) -> bool:
        holder = await self._core_api_client.get_holder_account(op_holder.address)

        msg: dict | None = None
        action = None

        if op_holder.address in self._blocked_holder_addr_dict:
            if not holder.is_empty:
                msg = log_msg("holder {Holder} for resource {Owner}:{ResourceID} is blocked")
                action = self._delete_holder_acct
            else:
                self._deleted_holder_addr_set.add(holder.address)
        elif holder.is_empty:
            action = self._create_holder_acct
        elif holder.size != self._holder_size:
            action = self._recreate_holder_acct
        elif holder.status == HolderAccountStatus.Active:
            tx_hash = holder.neon_tx_hash
            msg = log_msg("found stuck tx {Tx} in holder {Holder} for resource {Owner}:{ResourceID}", Tx=tx_hash)

        elif holder.status not in (HolderAccountStatus.Finalized, HolderAccountStatus.Holder):
            msg = log_msg("holder {Holder} has wrong tag {Tag} for resource {Owner}:{ResourceID}", Tag=holder.status)
            action = self._recreate_holder_acct

        else:
            msg = log_msg("use existing holder {Holder} for resource {Owner}:{ResourceID}")
            self._deleted_holder_addr_set.discard(holder.address)

        if msg:
            _LOG.debug(dict(**msg, Holder=op_holder.address, Owner=signer.pubkey, ResourceID=op_holder.resource_id))

        if action:
            return await action(signer, op_holder)
        return True

    async def _create_holder_acct(self, signer: SolSigner, op_holder: OpHolderInfo) -> bool:
        msg = log_msg(
            "create holder account {Holder} for resource {Owner}:{ResourceID}",
            Holder=op_holder.address,
            Owner=signer,
            ResourceID=op_holder.resource_id,
        )
        _LOG.debug(msg)

        sys_prog = SolSysProg()
        neon_prog = NeonProg(signer.pubkey).init_holder_address(op_holder.address)

        create_acct_ix = sys_prog.make_create_account_with_seed_ix(
            address=op_holder.address,
            owner=NeonProg.ID,
            payer=signer.pubkey,
            seed=op_holder.seed,
            balance=self._holder_balance,
            size=self._holder_size,
        )
        create_holder_ix = neon_prog.make_create_holder_ix(op_holder.seed)
        tx = SolLegacyTx(name="createHolderAccount", ix_list=tuple([create_acct_ix, create_holder_ix]))
        if result := await self._send_tx(signer, tx):
            self._deleted_holder_addr_set.discard(op_holder.address)
        return result

    async def _recreate_holder_acct(self, signer: SolSigner, op_holder: OpHolderInfo) -> bool:
        msg = log_msg(
            "recreate holder account {Holder} for resource {Owner}:{ResourceID}",
            Holder=op_holder.address,
            Owner=signer,
            ResourceID=op_holder.resource_id,
        )
        _LOG.debug(msg)
        return await self._delete_holder_acct(signer, op_holder) and await self._create_holder_acct(signer, op_holder)

    async def _delete_holder_acct(self, signer: SolSigner, op_holder: OpHolderInfo) -> bool:
        msg = log_msg(
            "delete holder account {Holder} for resource {Owner}:{ResourceID}",
            Holder=op_holder.address,
            Owner=signer,
            ResourceID=op_holder.resource_id,
        )
        _LOG.debug(msg)

        ix = NeonProg(signer.pubkey).init_holder_address(op_holder.address).make_delete_holder_ix()
        tx = SolLegacyTx(name="deleteHolderAccount", ix_list=tuple([ix]))
        if result := await self._send_tx(signer, tx):
            self._deleted_holder_addr_set.add(op_holder.address)
        return result

    async def _validate_neon_acct_list(self, op_signer: OpSignerInfo, evm_cfg: EvmConfigModel) -> bool:
        assert evm_cfg is not None

        prog = NeonProg(op_signer.owner)
        ix_list: list[SolTxIx] = list()
        token_sol_addr_dict: dict[int, SolPubKey] = dict()
        for token in evm_cfg.token_dict.values():
            acct = NeonAccount.from_raw(op_signer.eth_address, token.chain_id)
            model = await self._core_api_client.get_neon_account(acct, None)
            token_sol_addr_dict[token.chain_id] = model.sol_address
            if model.status == NeonAccountStatus.Ok:
                continue

            ix = prog.make_create_neon_account_ix(model.account, model.sol_address, model.contract_sol_address)
            ix_list.append(ix)

        if ix_list:
            tx = SolLegacyTx("createNeonAccount", ix_list=tuple(ix_list))
            if result := await self._send_tx(op_signer.signer, tx):
                op_signer.token_sol_address_dict = token_sol_addr_dict
            return result
        else:
            op_signer.token_sol_address_dict = token_sol_addr_dict
        return True

    async def _delete_signer_list(self) -> None:
        for op_signer in list(self._deactivated_signer_dict.values()):
            if await self._delete_holder_list(op_signer):
                # it is a possible case, when _refresh_signer_task activated the signer...
                if op_signer := self._deactivated_signer_dict.pop(op_signer.owner, None):
                    # all holders for the signer are deleted,
                    #   and as a result, there are no reasons to keep blocked accounts for deleted operator keys
                    for holder in op_signer.disabled_holder_list:
                        self._deleted_holder_addr_set.discard(holder.address)
                        self._blocked_holder_addr_dict.pop(holder.address, None)

    async def _delete_holder_list(self, op_signer: OpSignerInfo) -> bool:
        if op_signer.used_holder_dict:
            # if the key has a used holder -> wait till the tx process is finished
            return False
        elif not op_signer.free_holder_list:
            # no holders for removing
            return True

        holder: OpHolderInfo | None = None
        holder_list, op_signer.free_holder_list = op_signer.free_holder_list, deque()
        try:
            while holder_list:
                holder = holder_list.popleft()
                holder_acct = await self._core_api_client.get_holder_account(holder.address)
                if holder_acct.is_empty:
                    # holder doesn't exist
                    op_signer.disabled_holder_list.append(holder)
                    self._deleted_holder_addr_set.add(holder.address)
                elif await self._delete_holder_acct(op_signer.signer, holder):
                    # holder is successfully removed
                    op_signer.disabled_holder_list.append(holder)
                else:
                    # can't drop holder for some reason ...
                    op_signer.free_holder_list.append(holder)
            return not op_signer.free_holder_list
        except BaseException as exc:
            _LOG.error("error on removing holder accounts", exc_info=exc, extra=self._msg_filter)
            if holder:
                op_signer.free_holder_list.append(holder)
            op_signer.free_holder_list.extend(holder_list)
            return False

    async def _delete_blocked_holder_list(self) -> None:
        for holder_addr, owner in list(self._blocked_holder_addr_dict.items()):
            if holder_addr in self._deleted_holder_addr_set:
                continue

            if not (op_signer := self._active_signer_dict.get(owner, None)):
                _LOG.debug("no operator key %s for holder %s", owner, holder_addr)
                self._blocked_holder_addr_dict.pop(holder_addr)
                continue

            if holder_addr in op_signer.used_holder_dict:
                _LOG.debug("skip deletion of holder %s, because it's used in tx processing", holder_addr)
                continue

            if next((h for h in op_signer.disabled_holder_list if h.address == holder_addr), None):
                self._deleted_holder_addr_set.add(holder_addr)
                continue

            for holder in op_signer.free_holder_list:
                if holder.address == holder_addr:
                    _LOG.debug(
                        "found blocked holder %s for resource %s:%s",
                        holder_addr,
                        op_signer.owner,
                        holder.resource_id,
                    )
                    await self._delete_holder_acct(op_signer.signer, holder)
                    break
            else:
                _LOG.debug("operator key %s doesn't have holder %s", owner, holder_addr)
                self._blocked_holder_addr_dict.pop(holder_addr)

    async def _send_tx(self, signer: SolSigner, tx: SolTx) -> bool:
        return await self._send_tx_list(signer, tuple([tx]))

    async def _send_tx_list(self, signer: SolSigner, tx_list: Sequence[SolTx]) -> bool:
        tx_signer = OpTxListSigner(signer=signer)
        tx_sender = SolTxListSender(self._cfg, self._sol_watch_tx_session, tx_signer)
        try:
            return await tx_sender.send(tx_list)
        except BaseException as exc:
            _LOG.warning("error on execute transaction", exc_info=exc, extra=self._msg_filter)
            return False

    @reset_cached_method
    def _get_signer_key_list(self) -> tuple[SolPubKey, ...]:
        key_set = set(
            list(self._active_signer_dict.keys()) +
            list(self._deactivated_signer_dict.keys()) +
            list(self._disabled_signer_dict.keys())
        )
        return tuple(key_set)

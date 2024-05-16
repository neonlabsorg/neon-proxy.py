from __future__ import annotations

import logging
from typing import ClassVar

from common.ethereum.hash import EthTxHash, EthAddressField
from common.neon.account import NeonAccount
from common.neon.neon_program import NeonEvmIxCode
from common.neon.transaction_model import NeonTxModel
from common.solana.pubkey import SolPubKey, SolPubKeyField
from common.utils.pydantic import BaseModel
from .objects import BaseNeonIndexedObjInfo, NeonIndexedTxInfo, NeonIndexedHolderInfo, SolNeonDecoderCtx

_LOG = logging.getLogger(__name__)


class DummyIxDecoder:
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.Unknown
    is_deprecated: ClassVar[bool] = True

    def __init__(self, state: SolNeonDecoderCtx):
        self._state = state
        if self.ix_code != NeonEvmIxCode.Unknown:
            hdr = f"0x{self.ix_code.value:02x}:{self.ix_code.name} {self.state.sol_neon_ix}"
        else:
            hdr = f"0x{self.state.sol_neon_ix.neon_ix_code:02x}:{self.ix_code.name} {self.state.sol_neon_ix}"
        if self.is_deprecated:
            hdr = "DEPRECATED " + hdr
        _LOG.debug("%s ...", hdr)

    @property
    def is_stuck(self) -> bool:
        return False

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        ix = self.state.sol_neon_ix
        return self._decoding_skip("no logic to decode the instruction %s(%s)", ix.neon_ix_data.hex()[:8])

    def decode_failed_neon_tx_event_list(self) -> None:
        pass

    @property
    def state(self) -> SolNeonDecoderCtx:
        return self._state

    @staticmethod
    def _decoding_success(obj, msg: str, *args) -> bool:
        """The instruction has been successfully parsed."""
        _LOG.debug("decoding success: " + msg + " - %s", *args, obj)
        return True

    def _decoding_done(self, obj: BaseNeonIndexedObjInfo, msg: str, *args) -> bool:
        """Assembling of the object has been successfully finished."""
        block = self.state.neon_block
        if isinstance(obj, NeonIndexedTxInfo):
            block.done_neon_tx(obj)
        elif isinstance(obj, NeonIndexedHolderInfo):
            block.done_neon_holder(obj)
        _LOG.debug("decoding done: " + msg + " - %s", *args, obj)
        return True

    @staticmethod
    def _decoding_skip(reason: str, *args) -> bool:
        """Skip decoding of the instruction."""
        _LOG.warning("decoding skip: " + reason, *args)
        return False


class BaseTxIxDecoder(DummyIxDecoder):
    def _add_neon_indexed_tx(self) -> NeonIndexedTxInfo | None:
        if not (neon_tx := self._decode_neon_tx()):
            return None

        if not (holder_addr := self._get_holder_address()):
            return None

        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        return block.add_neon_tx(neon_tx, holder_addr, ix)

    def _decode_neon_tx(self) -> NeonTxModel | None:
        return NeonTxModel.from_raw(self.state.sol_neon_ix.neon_tx_hash)

    def _get_holder_address(self) -> SolPubKey | None:
        ix = self.state.sol_neon_ix
        if ix.account_key_cnt < 1:
            self._decoding_skip("no enough SolTxIx.Accounts(len=%s) to get NeonHolder.Account", ix.account_key_cnt)
            return None

        return ix.get_account_key(0)

    def _decode_neon_tx_from_rlp_data(
        self, data_name: str, eth_tx_rlp: bytes, start_rlp_pos: int = 0
    ) -> NeonTxModel | None:
        if len(eth_tx_rlp) < start_rlp_pos:
            self._decoding_skip("no enough %s(len=%s) to decode NeonTx", data_name, len(eth_tx_rlp))
            return None

        if start_rlp_pos > 0:
            eth_tx_rlp = eth_tx_rlp[start_rlp_pos:]

        ix = self.state.sol_neon_ix
        neon_tx = NeonTxModel.from_raw(eth_tx_rlp)
        if not neon_tx.is_valid:
            self._decoding_skip("%s.RLP.Error: '%s'", data_name, neon_tx.error)
            return None
        elif neon_tx.neon_tx_hash != ix.neon_tx_hash:
            # failed decoding ...
            self._decoding_skip("NeonTx.Hash '%s' != SolTxIx.Log.Hash '%s'", neon_tx.neon_tx_hash, ix.neon_tx_hash)
            return None
        return neon_tx

    def _decode_neon_tx_from_holder_data(self, holder: NeonIndexedHolderInfo) -> NeonTxModel | None:
        if not (neon_tx := self._decode_neon_tx_from_rlp_data("NeonHolder.Data", holder.data)):
            return None
        elif holder.neon_tx_hash != neon_tx.neon_tx_hash:
            # failed decoding ...
            self._decoding_skip("NeonTx.Hash '%s' != NeonHolder.Hash '%s'", neon_tx.neon_tx_hash, holder.neon_tx_hash)
            return None

        self._decoding_done(holder, "init NeonTx - %s from NeonHolder.Data", neon_tx)
        return neon_tx

    def _get_neon_tx_hash_from_ix_data(self, offset: int, min_len: int) -> EthTxHash | None:
        ix = self.state.sol_neon_ix

        if len(ix.neon_ix_data) < min_len:
            self._decoding_skip("no enough SolTxIx.Data(len=%s) to get NeonTx.Hash", len(ix.neon_ix_data))
            return None

        raw_tx_hash = ix.neon_ix_data[offset : (offset + 32)]  # noqa
        neon_tx_hash = EthTxHash.from_raw(raw_tx_hash)
        if ix.neon_tx_hash != neon_tx_hash:
            self._decoding_skip("NeonTx.Hash '%s' != SolTxIx.Log.Hash '%s'", neon_tx_hash, ix.neon_tx_hash)
            return None

        return neon_tx_hash

    def _decode_neon_tx_from_holder_account(self, tx: NeonIndexedTxInfo) -> bool:
        if tx.neon_tx.is_valid:
            return False

        ix = self.state.sol_neon_ix
        block = self.state.neon_block

        if not (holder := block.find_neon_tx_holder(tx.holder_address, ix)):
            return False

        if not (neon_tx := self._decode_neon_tx_from_holder_data(holder)):
            return False

        tx.set_neon_tx(neon_tx, holder)
        return True

    def _decode_neon_tx_receipt(self, tx: NeonIndexedTxInfo) -> bool:
        tx.extend_neon_tx_event_list(self.state.sol_neon_ix)
        if tx.is_completed:
            pass
        elif self._decode_neon_tx_return(tx):
            self._on_tx_return_event(tx)
            return True

        return False

    def _decode_neon_tx_return(self, tx: NeonIndexedTxInfo) -> bool:
        ix = self.state.sol_neon_ix
        tx_ret = ix.neon_tx_return
        if tx_ret.is_empty:
            return False

        tx.set_tx_return(ix, tx_ret)
        return True

    def _on_tx_return_event(self, tx: NeonIndexedTxInfo) -> None: ...


class BaseTxSimpleIxDecoder(BaseTxIxDecoder):
    def _decode_tx(self, msg: str) -> bool:
        if not (tx := self._add_neon_indexed_tx()):
            return False

        if not self._decode_neon_tx_receipt(tx):
            ix = self.state.sol_neon_ix
            tx.set_tx_lost_return(ix)

        self._decoding_done(tx, msg)
        return True


class TxExecFromDataIxDecoder(BaseTxSimpleIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.TxExecFromData
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._decode_tx("NeonTx exec from SolTxIx.Data")

    def _get_holder_address(self) -> SolPubKey | None:
        return SolPubKey.default()

    def _decode_neon_tx(self) -> NeonTxModel | None:
        # 1 byte  - ix
        # 4 bytes - treasury index
        # N bytes - NeonTx
        return self._decode_neon_tx_from_rlp_data("SolTxIx.Data", self.state.sol_neon_ix.neon_ix_data, start_rlp_pos=5)


class TxExecFromDataSolanaCallIxDecoder(TxExecFromDataIxDecoder):
    ix_code = NeonEvmIxCode.TxExecFromDataSolanaCall

    def execute(self) -> bool:
        return self._decode_tx(f"NeonTx(with SolanaCall) exec from SolIx.Data")


class TxExecFromAccountIxDecoder(BaseTxSimpleIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.TxExecFromAccount
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._decode_tx("NeonTx exec from NeonHolder.Data")

    def _on_tx_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)


class TxExecFromAccountSolanaCallIxDecoder(TxExecFromAccountIxDecoder):
    ix_code = NeonEvmIxCode.TxExecFromAccountSolanaCall

    def execute(self) -> bool:
        return self._decode_tx("NeonTx(with SolanaCall) exec from NeonHolder.Data")


class BaseTxStepIxDecoder(BaseTxIxDecoder):
    def _execute(self, msg: str) -> bool:
        if not (tx := self._get_neon_indexed_tx()):
            return False

        if self._decode_neon_tx_receipt(tx):
            return self._decoding_done(tx, msg)
        return self._decoding_success(tx, msg)

    def _get_neon_indexed_tx(self) -> NeonIndexedTxInfo | None:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        return block.find_neon_tx(ix) or self._add_neon_indexed_tx()

    def decode_failed_neon_tx_event_list(self) -> None:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        if not (tx := block.find_neon_tx(ix)):
            return

        tx.extend_neon_tx_event_list(ix)
        if ix.is_already_finalized and (not tx.is_completed):
            tx.set_tx_lost_return(ix)
            _LOG.warning("set lost result")
            self._decoding_done(tx, "complete by lost result")

    @property
    def is_stuck(self) -> bool:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        if tx := block.find_neon_tx(ix):
            return tx.is_stuck
        return False


class TxStepFromDataIxDecoder(BaseTxStepIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.TxStepFromData
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._execute("NeonTx step from SolTxIx.Data")

    def _decode_neon_tx(self) -> NeonTxModel | None:
        # 1 byte  - ix
        # 4 bytes - treasury index
        # 4 bytes - neon step cnt
        # 4 bytes - unique index
        # N bytes - NeonTx
        return self._decode_neon_tx_from_rlp_data("SolTxIx.Data", self.state.sol_neon_ix.neon_ix_data, start_rlp_pos=13)


class TxStepFromAccountIxDecoder(BaseTxStepIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.TxStepFromAccount
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._execute("NeonTx step from NeonHolder.Data")

    def _on_tx_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)


class TxStepFromAccountNoChainIdIxDecoder(BaseTxStepIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.TxStepFromAccountNoChainId
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._execute("NeonTx-wo-ChainId step from NeonHolder.Data")

    def _on_tx_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)


class CancelWithHashIxDecoder(BaseTxStepIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.CancelWithHash
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        # 1  byte  - ix
        # 32 bytes - tx hash

        if not (neon_tx_hash := self._get_neon_tx_hash_from_ix_data(1, 33)):
            return False

        if not (tx := self._get_neon_indexed_tx()):
            return self._decoding_skip("cannot find NeonTx '%s'", neon_tx_hash)

        if tx.is_completed:
            return self._decoding_skip("NeonTx %s is already has NeonReceipt", neon_tx_hash)

        self._decode_neon_tx_receipt(tx)
        return self._decoding_done(tx, "cancel NeonTx")

    def _decode_neon_tx_return(self, tx: NeonIndexedTxInfo) -> bool:
        ix = self.state.sol_neon_ix
        self._decode_neon_tx_from_holder_account(tx)
        tx.set_tx_cancel_return(ix)
        return True


class WriteHolderAccountIx(BaseTxIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.HolderWrite
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        if not (holder_addr := self._get_holder_address()):
            return False

        # 1  byte  - ix
        # 32 bytes - tx hash
        # 8  bytes - offset

        if not (_neon_tx_hash := self._get_neon_tx_hash_from_ix_data(1, 42)):
            return False

        ix = self.state.sol_neon_ix
        block = self.state.neon_block

        data = ix.neon_ix_data[41:]
        offset = int.from_bytes(ix.neon_ix_data[33:41], "little")
        chunk = NeonIndexedHolderInfo.DataChunk(offset=offset, length=len(data), data=data)

        tx: NeonIndexedTxInfo | None = block.find_neon_tx(ix)
        if (tx is not None) and tx.neon_tx.is_valid:
            return self._decoding_success(tx, "add surplus NeonTx.Data.Chunk to NeonTx")

        holder: NeonIndexedHolderInfo = block.find_or_add_neon_tx_holder(holder_addr, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        self._decoding_success(holder, "add NeonTx.Data.Chunk %s", chunk)

        if tx is None:
            return True

        if neon_tx := self._decode_neon_tx_from_holder_data(holder):
            tx.set_neon_tx(neon_tx, holder)

        return True


class CreateBalanceIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.CreateAccountBalance
    is_deprecated: ClassVar[bool] = False

    class _NeonAccountModel(BaseModel):
        neon_address: EthAddressField
        chain_id: int
        sol_address: SolPubKeyField
        contract_sol_address: SolPubKeyField

    def execute(self) -> bool:
        """
        Just for information in the Indexer logs.
        Accounts in 99.99% of cases are created inside the EVM bytecode, and NeonEVM doesn't inform about them.
        This event happens only in two cases:
        1. Fee-Less transaction for not-exist absent account
        2. Operator account.
        """
        ix = self.state.sol_neon_ix
        ix_data = ix.neon_ix_data
        if len(ix_data) < 29:
            return self._decoding_skip("not enough data to get NeonAccount.NeonAddress.ChainId %s", len(ix_data))

        acct = self._NeonAccountModel(
            neon_address=ix_data[1:21],
            chain_id=int.from_bytes(ix_data[21:29], byteorder="little"),
            sol_address=ix.get_account_key(2),
            contract_sol_address=ix.get_account_key(3),
        )

        return self._decoding_success(acct, "create NeonAccount")


class CollectTreasureIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.CollectTreasure
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._decoding_success(None, "collect NeonTreasury")


class BaseHolderAccountIx(BaseTxIxDecoder):
    def _execute(self, name: str) -> bool:
        if not (holder_addr := self._get_holder_address()):
            return False

        block = self.state.neon_block
        block.destroy_neon_holder(holder_addr)
        return self._decoding_success(holder_addr, name)


class CreateHolderAccountIx(BaseHolderAccountIx):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.HolderCreate
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._execute("create HolderAccount")


class DeleteHolderAccountIx(BaseHolderAccountIx):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.HolderDelete
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._execute("delete HolderAccount")


class DepositIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.Deposit
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        return self._decoding_success(None, "deposit NEONs")


class CreateOperatorBalanceIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.CreateOperatorBalance
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        """Just for information in the Indexer logs."""

        ix = self.state.sol_neon_ix
        ix_data = ix.neon_ix_data

        # 20 bytes: ETH address
        # 8 bytes: chain-id
        if len(ix_data) < 28:
            return self._decoding_skip("not enough data to get Operator.NeonAddress.ChainId %s", len(ix_data))

        neon_acct = NeonAccount.from_raw(ix_data[:20], int.from_bytes(ix_data[20:8], "little"))
        return self._decoding_success(neon_acct, "create Operator Balance")


class DeleteOperatorBalanceIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.DeleteOperatorBalance
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        """Just for information in the Indexer logs."""
        return self._decoding_success(None, "delete Operator Balance")


class WithdrawOperatorBalanceIxDecoder(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.WithdrawOperatorBalance
    is_deprecated: ClassVar[bool] = False

    def execute(self) -> bool:
        """Just for information in the Indexer logs."""
        return self._decoding_success(None, "withdraw Operator Balance")


def get_neon_ix_decoder_list() -> list[type[DummyIxDecoder]]:
    ix_decoder_list = [
        TxExecFromDataIxDecoder,
        TxExecFromDataSolanaCallIxDecoder,
        TxExecFromAccountIxDecoder,
        TxExecFromAccountSolanaCallIxDecoder,
        TxStepFromDataIxDecoder,
        TxStepFromAccountIxDecoder,
        TxStepFromAccountNoChainIdIxDecoder,
        CancelWithHashIxDecoder,
        WriteHolderAccountIx,
        CreateBalanceIxDecoder,
        CollectTreasureIxDecoder,
        CreateHolderAccountIx,
        DeleteHolderAccountIx,
        DepositIxDecoder,
        CreateOperatorBalanceIxDecoder,
        DeleteOperatorBalanceIxDecoder,
        WithdrawOperatorBalanceIxDecoder,
    ]

    for IxDecoder in ix_decoder_list:
        assert not IxDecoder.is_deprecated, f"{IxDecoder.ix_code.name} is deprecated!"

    return ix_decoder_list

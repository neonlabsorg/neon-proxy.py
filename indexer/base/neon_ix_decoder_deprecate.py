from __future__ import annotations

from typing import ClassVar

from common.ethereum.hash import EthAddressField
from common.neon.neon_program import NeonEvmIxCode
from common.solana.pubkey import SolPubKeyField
from common.utils.pydantic import BaseModel
from .neon_ix_decoder import (
    DummyIxDecoder,
    TxExecFromDataIxDecoder,
    TxExecFromAccountIxDecoder,
    TxStepFromDataIxDecoder,
    TxStepFromAccountIxDecoder,
    TxStepFromAccountNoChainIdIxDecoder,
    CancelWithHashIxDecoder,
)


class OldTxExecFromDataIxDecoderV1004(TxExecFromDataIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxExecFromDataV1004
    is_deprecated: ClassVar[bool] = True


class OldTxExecFromAccountIxDecoderV1004(TxExecFromAccountIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxExecFromAccountV1004
    is_deprecated: ClassVar[bool] = True


class OldTxStepFromAccountIxDecoderV1004(TxStepFromAccountIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxStepFromAccountV1004
    is_deprecated: ClassVar[bool] = True


class OldTxStepFromDataIxDecoderV1004(TxStepFromDataIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxStepFromDataV1004
    is_deprecated: ClassVar[bool] = True


class OldTxStepFromAccountNoChainIdIxDecoderV1004(TxStepFromAccountNoChainIdIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxStepFromAccountNoChainIdV1004
    is_deprecated: ClassVar[bool] = True


class OldCancelWithHashIxDecoderV1004(CancelWithHashIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldCancelWithHashV1004
    is_deprecated: ClassVar[bool] = True


class OldCreateAccountIxDecoderV1004(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldCreateAccountV1004
    is_deprecated: ClassVar[bool] = True

    class _NeonAccountModel(BaseModel):
        neon_address: EthAddressField
        sol_address: SolPubKeyField

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
        if len(ix_data) < 21:
            return self._decoding_skip("not enough data to get NeonAccount %s", len(ix_data))

        acct = self._NeonAccountModel(
            neon_address=ix_data[1:21],
            sol_address=ix.get_account_key(2),
        )
        return self._decoding_success(acct, "create NeonAccount")


class OldDepositIxDecoderV1004(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldDepositV1004
    is_deprecated: ClassVar[bool] = True

    def execute(self) -> bool:
        return self._decoding_success(None, "deposit NEONs")


def get_neon_ix_decoder_deprecated_list() -> list[type[DummyIxDecoder]]:
    ix_decoder_list: list[type[DummyIxDecoder]] = [
        OldTxExecFromDataIxDecoderV1004,
        OldTxExecFromAccountIxDecoderV1004,
        OldTxStepFromDataIxDecoderV1004,
        OldTxStepFromAccountIxDecoderV1004,
        OldTxStepFromAccountNoChainIdIxDecoderV1004,
        OldCreateAccountIxDecoderV1004,
        OldDepositIxDecoderV1004,
    ]
    for IxDecoder in ix_decoder_list:
        assert IxDecoder.is_deprecated, f"{IxDecoder.ix_code.name} is NOT deprecated!"

    return ix_decoder_list

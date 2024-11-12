from __future__ import annotations

import logging
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

_LOG = logging.getLogger(__name__)


class OldTxExecFromDataIxDecoderV1013(TxExecFromDataIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxExecFromDataV1013
    is_deprecated: ClassVar[bool] = True


class OldTxExecFromDataSolanaCallIxDecoderV1013(TxExecFromDataIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldTxExecFromDataSolanaCallV1013
    is_deprecated: ClassVar[bool] = True


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
            _LOG.warning("%s: not enough data to get NeonAccount %d", self._skip_hdr, len(ix_data))
            return False

        acct = self._NeonAccountModel(
            neon_address=ix_data[1:21],
            sol_address=ix.get_account_key(2),
        )
        _LOG.debug("%s: create NeonAccount - %s", self._success_hdr, acct)
        return True


class OldDepositIxDecoderV1004(DummyIxDecoder):
    ix_code: ClassVar[NeonEvmIxCode] = NeonEvmIxCode.OldDepositV1004
    is_deprecated: ClassVar[bool] = True

    def execute(self) -> bool:
        _LOG.debug("%s: deposit NEONs", self._success_hdr)
        return True


def get_neon_ix_decoder_deprecated_list() -> list[type[DummyIxDecoder]]:
    ix_decoder_list: list[type[DummyIxDecoder]] = [
        OldTxExecFromDataIxDecoderV1013,
        OldTxExecFromDataSolanaCallIxDecoderV1013,
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

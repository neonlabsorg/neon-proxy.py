from __future__ import annotations

from typing import Dict, Any, List

from eth_account import Account as NeonAccount

from ..common_neon.address import NeonAddress
from ..common_neon.errors import EthereumError, InvalidParamError
from ..common_neon.eth_commit import EthCommit
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.utils import NeonTxInfo
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.utils.utils import hex_to_bytes


class NeonRpcApiWorker:

    @staticmethod
    def eth_accounts() -> [str]:
        storage = KeyStorage()
        account_list = storage.get_list()
        return [a.checksum_address for a in account_list]

    def eth_sign(self, account: str, data: str) -> str:
        address = self._normalize_address(account)
        try:
            data = hex_to_bytes(data)
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private_key.sign_msg(message))

    def eth_signTransaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        del tx['from']
        sender = self._normalize_address(sender, 'from-address')

        if 'to' in tx:
            tx['to'] = self._normalize_address(tx['to'], 'to-address').checksum_address

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender.address, EthCommit.Pending)

        if 'chainId' not in tx:
            tx['chainId'] = hex(self._chain_id)

        try:
            signed_tx = NeonAccount().sign_transaction(tx, account.private_key)
            raw_tx = signed_tx.rawTransaction.hex()
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))

            tx.update({
                'from': sender.checksum_address,
                'hash': neon_tx.hex_tx_sig,
                'r': hex(neon_tx.r),
                's': hex(neon_tx.s),
                'v': hex(neon_tx.v)
            })

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except BaseException as exc:
            LOG.error('Failed on sign transaction', exc_info=exc)
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: Dict[str, Any]) -> str:
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])


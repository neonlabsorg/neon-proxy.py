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


    @staticmethod
    def _mp_pool_tx(neon_tx_info: NeonTxInfo) -> Dict[str, Any]:
        to_addr = NeonAddress.from_raw(neon_tx_info.to_addr)
        if to_addr:
            to_addr = to_addr.checksum_address

        return {
            'blockHash': '0x' + '0' * 64,
            'blockNumber': None,
            'transactionIndex': None,
            'from': NeonAddress.from_raw(neon_tx_info.addr).checksum_address,
            'gas': hex(neon_tx_info.gas_limit),
            'gasPrice': hex(neon_tx_info.gas_price),
            'hash': neon_tx_info.sig,
            'input': neon_tx_info.calldata,
            'nonce': hex(neon_tx_info.nonce),
            'to': to_addr,
            'value': hex(neon_tx_info.value),
            'chainId': hex(neon_tx_info.chain_id) if neon_tx_info.has_chain_id else None
        }

    def _mp_pool_queue(self, tx_list: List[NeonTxInfo]) -> Dict[str, Any]:
        sender_addr = ''
        sender_pool: Dict[int, Any] = dict()
        sender_pool_dict: Dict[str, Any] = dict()
        for tx in tx_list:
            if sender_addr != tx.addr and len(sender_addr):
                sender_pool_dict[sender_addr] = sender_pool
                sender_pool = dict()

            sender_addr = tx.addr
            sender_pool[tx.nonce] = self._mp_pool_tx(tx)

        if sender_addr:
            sender_pool_dict[sender_addr] = sender_pool

        return sender_pool_dict

    def txpool_content(self) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = dict()

        req_id = get_req_id_from_log()
        content = self._mempool_client.get_content(req_id)

        result_dict['pending'] = self._mp_pool_queue(content.pending_list)
        result_dict['queued'] = self._mp_pool_queue(content.queued_list)
        return result_dict


import unittest
from typing import List

from testing.testing_helpers import Proxy, TxReceipt


class TestDistributorContract(unittest.TestCase):
    WAITING_DISTRIBUTE_RECEIPT_TIMEOUT_SEC = 15
    WAITING_SET_ADDRESS_RECEIPT_TIMEOUT_SEC = 10

    def setUp(self) -> None:
        self.proxy = Proxy()
        signer = self.proxy.create_signer_account()
        self.contract = self.proxy.compile_and_deploy_from_file(
            signer, "./proxy/testing/solidity_contracts/NeonDistributor.sol"
        ).contract

    def test_distribute_tx_affects_multiple_accounts(self):
        signer = self.proxy.create_signer_account()
        wallets = self.generate_wallets()
        self._set_and_check_distributor_addresses(wallets, signer)

        distribute_value_fn = self.contract.functions.distribute_value()
        nonce = self.proxy.conn.get_transaction_count(signer.address)
        tx_built = distribute_value_fn.build_transaction({"nonce": nonce})
        tx_built["value"] = 12
        distribute_fn_msg = signer.sign_transaction(tx_built)
        neon_tx_hash = self.proxy.conn.send_raw_transaction(distribute_fn_msg.rawTransaction)
        print(f"Send `distribute_value_fn()` tx with nonce: {nonce}, neon_tx_hash: 0x{tx_hash.hex()}")
        print(f"Wait for `distribute_value_fn` receipt by hash: 0x{tx_hash.hex()}")
        tx_receipt = self.proxy.conn.wait_for_transaction_receipt(
            neon_tx_hash,
            timeout=self.WAITING_DISTRIBUTE_RECEIPT_TIMEOUT_SEC
        )
        self.assertEqual(tx_receipt.status, 1)

    def _set_and_check_distributor_addresses(self, wallets, signer):
        nonce: int = self.proxy.get_transaction_count(signer.address, 'pending')
        prebuilt_txs = []

        for name, account in wallets.items():
            set_address_fn = self.contract.functions.set_address(name, bytes.fromhex(account.address[2:]))
            set_address_fn_tx_built = set_address_fn.build_transaction({"nonce": nonce})
            set_address_msg = signer.sign_transaction(set_address_fn_tx_built)
            prebuilt_txs.append((set_address_msg.rawTransaction, name, account, nonce))
            nonce += 1

        neon_tx_hashes: List[TxReceipt] = []
        for prebuilt_tx in prebuilt_txs:
            raw_tx, name, account, nonce = prebuilt_tx
            neon_tx_hash = self.proxy.conn.send_raw_transaction(raw_tx)
            print(
                f'Send `set_address_fn("{name}", {account.address[2:]}`) '
                f"tx with nonce: {nonce}, neon_tx_hash: {neon_tx_hash.hex()}"
            )
            neon_tx_hashes.append(neon_tx_hash)

        for neon_tx_hash in neon_tx_hashes:
            tx_receipt = self.proxy.conn.wait_for_transaction_receipt(
                neon_tx_hash,
                timeout=self.WAITING_SET_ADDRESS_RECEIPT_TIMEOUT_SEC
            )
            self.assertEqual(tx_receipt.status, 1)

    def generate_wallets(self):
        names = [
            "alice", "bob", "carol", "dave", "erine", "eve", "frank",
            "mallory", "pat", "peggy", "trudy", "vanna", "victor"
        ]
        wallets = {name: self.proxy.create_account() for name in names}
        return wallets


if __name__ == '__main__':
    unittest.main()

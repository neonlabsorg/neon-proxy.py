import unittest

from common.ethereum.hash import EthTxHash
from common.solana.pubkey import SolPubKey
from indexer.base.objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonIndexedAltInfo


class TestMigrate(unittest.TestCase):
    def test_alt(self) -> None:
        old_data_list = [
            {
                "alt_key": "CfRb2c6Jurm3yNQrJkzYjv5W5Tn9JXQDvKTSwBSYGiyW",
                "neon_tx_sig": "0xa81914a33b41a616d821447168def9d0b82021c7620e55112aebbc1107f72445",
                "block_slot": 8613,
                "next_check_slot": 9051,
                "last_ix_slot": 8703,
                "is_stuck": False,
            }
        ]
        for data in old_data_list:
            old = NeonIndexedAltInfo._DeprecatedInitData.from_dict(data)
            new = old.to_clean_copy()
            self.assertEqual(new.neon_tx_hash, EthTxHash.from_raw(old.neon_tx_sig))
            self.assertEqual(new.key, SolPubKey.from_raw(old.alt_key))

            alt = NeonIndexedAltInfo.from_dict(data)
            self.assertEqual(alt.neon_tx_hash, new.neon_tx_hash)

    def test_holder(self) -> None:
        old_data_list = [
            {
                "start_block_slot": 8373,
                "last_block_slot": 8373,
                "is_stuck": True,
                "neon_tx_sig": "0x7f3d507c443a83e3f562fe3fdbb42533c0556e857ff8ba9903cc5a6a5ceea941",
                "account": "FnVEN7TcDCs6ZojAv9XH2DzZrqinN3Y6Xir2hmNfkUTM",
                "data_size": 109,
                "data": "f86b01847735940084093d5c80941d930b195408ac83c7a5181497cf7b8e0abb683980843467b950820102a0ac53a5a39cc2c7f218aab1d54eda41fa7238915b0ff1d4a4f6750b62c124f27aa0242901f36d06824858ae3af6fefbc163e4cf23226a1e104638e309e9a01f2032",
            }
        ]
        for data in old_data_list:
            old = NeonIndexedHolderInfo._DeprecatedInitData.from_dict(data)
            new = old.to_clean_copy()
            self.assertEqual(new.neon_tx_hash, EthTxHash.from_raw(old.neon_tx_sig))

            holder = NeonIndexedHolderInfo.from_dict(data)
            self.assertEqual(holder.neon_tx_hash, new.neon_tx_hash)

    def test_tx(self) -> None:
        old_data_list = [
            {
                "start_block_slot": 186,
                "last_block_slot": 186,
                "is_stuck": True,
                "ix_code": 52,
                "neon_tx_sig": "0x11a8cff4465bf0b8adfaf7ca4e12e35be26abb33203bb2cc69c991ed05e314cd",
                "holder_account": "HcV5TabWzD28Z6jeuTQmKUKLQpJksb9Q1J4EStfPTbLS",
                "operator": "BMp6gEnveANdvSvspESJUrNczuHz1GF5UQKjVLCkAZih",
                "gas_used": 5000,
                "total_gas_used": 5000,
                "neon_tx": {
                    "addr": "0x2cd3b3b4e55faa5423d6d08aaf1c7697412a0d74",
                    "sig": "0x11a8cff4465bf0b8adfaf7ca4e12e35be26abb33203bb2cc69c991ed05e314cd",
                    "tx_type": 0,
                    "nonce": 3,
                    "gas_price": 0,
                    "gas_limit": 25000,
                    "to_addr": "0xbc961175565ee433eeefafa2bd0222ed55a26ba0",
                    "contract": None,
                    "value": 0,
                    "calldata": "0x6268c75400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001",
                    "v": 258,
                    "r": 39491310016330199094743051874658927128149628827368076843770909007355662264638,
                    "s": 9666960142482451915193350048542304742143748345168913799096315766466682281958,
                    "error": None,
                },
                "neon_tx_res": {
                    "block_slot": None,
                    "block_hash": None,
                    "tx_idx": None,
                    "sol_sig": None,
                    "sol_ix_idx": None,
                    "sol_ix_inner_idx": None,
                    "neon_sig": "",
                    "status": 0,
                    "gas_used": 0,
                    "sum_gas_used": 0,
                    "event_list": [],
                },
                "neon_tx_event_list": [
                    {
                        "event_type": 101,
                        "is_hidden": True,
                        "address": "0xbc961175565ee433eeefafa2bd0222ed55a26ba0",
                        "topic_list": [],
                        "data": "0x",
                        "sol_sig": "4BvSZv6fRcjwvRRjPrSTvSkwEhwh7ahF1WKhr9HriVYESvaEAvfvr6md51WAb5QckB1jZ1YJNpUX2cEvNxotqYm5",
                        "idx": 2,
                        "inner_idx": None,
                        "total_gas_used": 5000,
                        "is_reverted": False,
                        "event_level": 0,
                        "event_order": 0,
                        "neon_sig": "",
                        "block_hash": "",
                        "block_slot": 0,
                        "neon_tx_idx": 0,
                        "block_log_idx": None,
                        "neon_tx_log_idx": None,
                    }
                ],
            },
            {
                "start_block_slot": 192,
                "last_block_slot": 192,
                "is_stuck": True,
                "ix_code": 52,
                "neon_tx_sig": "0xa996d1724832262bf5c76842dc2207acb8e70c6fd5418be5a20f347118f27308",
                "holder_account": "HNaUNf2PWS4DNPs1LEAttzFxP3iUiRG6NRXVSUFLzasu",
                "operator": "BMp6gEnveANdvSvspESJUrNczuHz1GF5UQKjVLCkAZih",
                "gas_used": 5000,
                "total_gas_used": 5000,
                "neon_tx": {
                    "addr": "0xec077a1ce3efef71fd8dd1d48e74c334a94e62a9",
                    "sig": "0xa996d1724832262bf5c76842dc2207acb8e70c6fd5418be5a20f347118f27308",
                    "tx_type": 0,
                    "nonce": 1,
                    "gas_price": 2000000000,
                    "gas_limit": 987654321,
                    "to_addr": "0x4fe8e258f191da8af67cb189591cba09c147b56c",
                    "contract": None,
                    "value": 500000000000000000,
                    "calldata": "0x",
                    "v": 258,
                    "r": 51054122085676688786384601348476056992302764945238825130916574821493213635212,
                    "s": 29169421175823543001953496567389926424882327980499297162490900933780641476221,
                    "error": None,
                },
                "neon_tx_res": {
                    "block_slot": None,
                    "block_hash": None,
                    "tx_idx": None,
                    "sol_sig": None,
                    "sol_ix_idx": None,
                    "sol_ix_inner_idx": None,
                    "neon_sig": "",
                    "status": 0,
                    "gas_used": 0,
                    "sum_gas_used": 0,
                    "event_list": [],
                },
                "neon_tx_event_list": [
                    {
                        "event_type": 101,
                        "is_hidden": True,
                        "address": "0x4fe8e258f191da8af67cb189591cba09c147b56c",
                        "topic_list": [
                            "0xa996d1724832262bf5c76842dc2207acb8e70c6fd5418be5a20f347118f27308",
                            "0xa996d1724835262bf5c76842dc2207acb8e70c98d5418be5a20f347118f27308",
                        ],
                        "data": "0x4fe8e258f191da8af67cb189591cba09c147b56c",
                        "sol_sig": "5guxHz884KrqvcYdxxwpwAzuH3txoeHh9XQRTEkMm1iqKFCYmybsKnzXMZw9CFu7Hr4MvujGn5pjsuLzTnfUmxyJ",
                        "idx": 2,
                        "inner_idx": 0,
                        "total_gas_used": 5000,
                        "is_reverted": False,
                        "event_level": 0,
                        "event_order": 0,
                        "neon_sig": "",
                        "block_hash": "",
                        "block_slot": 0,
                        "neon_tx_idx": 0,
                        "block_log_idx": None,
                        "neon_tx_log_idx": None,
                    }
                ],
            },
        ]
        for data in old_data_list:
            old = NeonIndexedTxInfo._DeprecatedInitData.from_dict(data)
            new = old.to_clean_copy()
            self.assertEqual(new.neon_tx_hash, EthTxHash.from_raw(old.neon_tx_sig))
            self.assertEqual(len(new.neon_tx_event_list), len(old.neon_tx_event_list))

            tx = NeonIndexedTxInfo.from_dict(data)
            self.assertEqual(tx.neon_tx_hash, new.neon_tx_hash)


if __name__ == "__main__":
    unittest.main()

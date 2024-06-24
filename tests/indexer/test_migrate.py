import pickle
import unittest

from common.ethereum.hash import EthTxHash
from common.solana.pubkey import SolPubKey
from indexer.base.objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonIndexedAltInfo
from indexer.db.neon_tx_db import _RecordWithBlock


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

    def test_old_tx_log(self):
        value = b'\x80\x05\x95\xae"\x00\x00\x00\x00\x00\x00]\x94(}\x94(\x8c\x07address\x94\x8c*0x43de2d77bf8027e25dbd179b491e8d64f38398aa\x94\x8c\x06topics\x94]\x94\x8c\x04data\x94\x8c\x00\x94\x8c\x0bneonSolHash\x94\x8cX2vw2MnG2ytcrxs1a4Y88tg6epsSAmYeca29uPw72NLMBBUJWS24v5VkKYXjSWzx47TeMj5cdn7RdQEXSXbK7yWK3\x94\x8c\tneonIxIdx\x94K\x03\x8c\x0eneonInnerIxIdx\x94N\x8c\rneonEventType\x94Ke\x8c\x0eneonEventLevel\x94K\x01\x8c\x0eneonEventOrder\x94K\x01\x8c\x0cneonIsHidden\x94\x88\x8c\x0eneonIsReverted\x94\x89\x8c\x0ftransactionHash\x94\x8cB0x4fb15925c80f2e6b4be914b2bd4cca27840c6d47cc537d3404ef3432f39ef9d0\x94\x8c\tblockHash\x94\x8cB0x2c7ba80e730d8e3e8757037ffd7f08fb9571f113940a1d625c317e7894b3d2c0\x94\x8c\x0bblockNumber\x94\x8c\n0x103a3634\x94\x8c\x10transactionIndex\x94\x8c\x030x0\x94u}\x94(h\x02\x8c*0xb1a20d1c885fd775df97396397d6f8f07abdd20d\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x02h\x0eK\x02h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKeh\rK\x03h\x0eK\x03h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x2a3e72ed893b5958690e16c3bbe1bd92137b6250\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x04h\x0eK\x04h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x05h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x06h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff89350000000000000000000000001c0720b124e7251e881a0fbcfe259d085c59f205\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\x07h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18\x8c\x08logIndex\x94\x8c\x030x0\x94\x8c\x13transactionLogIndex\x94\x8c\x030x0\x94u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x08h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\th\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff89350000000000000000000000004bc16662a2ce381e7bb54dc577c05619c5e67526\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\nh\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x1\x94h.\x8c\x030x1\x94u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x0bh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x0ch\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff89350000000000000000000000004ca2191cde585d65eb6afc09d23d60b8a0ab677d\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\rh\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x2\x94h.\x8c\x030x2\x94u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x0eh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x0fh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff893500000000000000000000000059ce95b8955f0e7be128d5af77161b36f6084214\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\x10h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x3\x94h.\x8c\x030x3\x94u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x11h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x12h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff89350000000000000000000000006436bbca322b8cd0c56d8b9ad7837b13960da426\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\x13h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x4\x94h.\x8c\x030x4\x94u}\x94(h\x02\x8c*0x0000000000000000000000000000000000000001\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x05h\x0eK\x14h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x15h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0xd4964a7cd99f5c1fa8f2420fb5e1d3bd26eadf16e2658cf2e29a67dfda38601e\x94ah\x06\x8c\x820xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff893500000000000000000000000083f81e7f9e284aaffeded797008663595f7342bf\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\x16h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x5\x94h.\x8c\x030x5\x94u}\x94(h\x02\x8c*0x949b3b3c098348b879c9e4f15cecc8046d9c8a8c\x94h\x04]\x94\x8cB0x2a6b4960c287d4d53a338f9c9a9f830f37e7b66e67a0a958f68be89a4eeb939d\x94ah\x06\x8cB0xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff8935\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK\x17h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x6\x94h.\x8c\x030x6\x94u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xc9h\rK\x04h\x0eK\x18h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x03h\x0eK\x19h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1ed606683a3f89317d64bda602628d68a0b4b24\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKeh\rK\x03h\x0eK\x1ah\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x8244d6ffe0695b30b2bad424683ee3bc534ea464\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x04h\x0eK\x1bh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x4c7ca8fcffe77281a8b81d4580cff8257d785491\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x05h\x0eK\x1ch\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK\x1dh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x04h\x0eK\x1eh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1656b63d9eeba6d114f6be19565177893e5bcbf\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x04h\x0eK\x1fh\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1ed606683a3f89317d64bda602628d68a0b4b24\x94h\x04]\x94(\x8cB0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\x94\x8cB0x0000000000000000000000000000000000000000000000000000000000000000\x94\x8cB0x000000000000000000000000d4aaee7d76a1603ee23af1ba7e5c977364ec30a4\x94eh\x06\x8cB0x0000000000000000000000000000000000000000000000003a765a7e4fa0e000\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x7\x94h.\x8c\x030x7\x94u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xc9h\rK\x04h\x0eK!h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x03h\x0eK"h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1ed606683a3f89317d64bda602628d68a0b4b24\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKeh\rK\x03h\x0eK#h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x8244d6ffe0695b30b2bad424683ee3bc534ea464\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x04h\x0eK$h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x4c7ca8fcffe77281a8b81d4580cff8257d785491\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x05h\x0eK%h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK&h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x04h\x0eK\'h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1656b63d9eeba6d114f6be19565177893e5bcbf\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x04h\x0eK(h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1ed606683a3f89317d64bda602628d68a0b4b24\x94h\x04]\x94(\x8cB0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\x94\x8cB0x0000000000000000000000000000000000000000000000000000000000000000\x94\x8cB0x000000000000000000000000d4aaee7d76a1603ee23af1ba7e5c977364ec30a4\x94eh\x06\x8cB0x00000000000000000000000000000000000000000000070fd8b9fde398678400\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x04h\x0eK)h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x8\x94h.\x8c\x030x8\x94u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xc9h\rK\x04h\x0eK*h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x03h\x0eK+h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1ed606683a3f89317d64bda602628d68a0b4b24\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x03h\x0eK,h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x8244d6ffe0695b30b2bad424683ee3bc534ea464\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKgh\rK\x04h\x0eK-h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x4c7ca8fcffe77281a8b81d4580cff8257d785491\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x05h\x0eK.h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x05h\x0eK/h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x04h\x0eK0h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0xc1656b63d9eeba6d114f6be19565177893e5bcbf\x94h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cKhh\rK\x04h\x0eK1h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x04h\x0eK2h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x03h\x0eK3h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02\x8c*0x43de2d77bf8027e25dbd179b491e8d64f38398aa\x94h\x04]\x94\x8cB0xe16b3d616e66789124fb71bf745a9a969a79906489c299e52e09686696152ef1\x94ah\x06\x8c\xc20xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff893500000000000000000000000000000000000000000000cfb9ed3907cbb5f1f20000000000000000000000000000000000000000000000cfb9ed3907cbb5f1f200\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x02h\x0eK4h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030x9\x94h.\x8c\x030x9\x94u}\x94(h\x02\x8c*0x43de2d77bf8027e25dbd179b491e8d64f38398aa\x94h\x04]\x94(\x8cB0xfee5cae6d86f128037e90fc8d24296e73ad402bd6f6f09098589d528c2e14ad2\x94\x8cB0x1d5f00e94eafba09fb7d0d9204c3a1608c47f85f574e5c64db4cd97912223b3c\x94\x8cB0x000000000000000000000000d4aaee7d76a1603ee23af1ba7e5c977364ec30a4\x94\x8cB0x0000000000000000000000000000000000000000000000000000000000000001\x94eh\x06X\xc2\x03\x00\x000xb2668393bbd25cb59cc172caef757e6d7870023134d6f4c900391ac9b0ff893500000000000000000000000000000000000000000000070fd8b9fde39867840000000000000000000000000000000000000000000000000000000000000077e700000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000003a765a7e4fa0e0000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000d4aaee7d76a1603ee23af1ba7e5c977364ec30a400000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d4aaee7d76a1603ee23af1ba7e5c977364ec30a4000000000000000000000000\x94h\x08h\th\nK\x03h\x0bNh\x0cK\x01h\rK\x02h\x0eK5h\x0f\x89h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18h,\x8c\x030xa\x94h.\x8c\x030xa\x94u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xc9h\rK\x02h\x0eK6h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06h\x07h\x08h\th\nK\x03h\x0bNh\x0cK\xcah\rK\x01h\x0eK7h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18u}\x94(h\x02h\x07h\x04]\x94h\x06\x8c\x040x01\x94h\x08h\th\nK\x03h\x0bNh\x0cM,\x01h\rK\x00h\x0eK8h\x0f\x88h\x10\x89h\x11h\x12h\x13h\x14h\x15h\x16h\x17h\x18ue.'

        log_list = _RecordWithBlock._decode_event_list(value)
        self.assertEqual(len(log_list), 56)


if __name__ == "__main__":
    unittest.main()

import unittest

from pydantic import BaseModel

from common.neon.account import NeonAccount, NeonAccountField, eth_keys
from common.utils.format import hex_to_bytes


class TestNeonAccount(unittest.TestCase):
    def test_from_dict(self):
        raw_dict = {
            "address": "24a461e3e0e129f6d19ccf11f3b4d6b4d3a36d2a",
            "chain_id": "1abe42",
            "private_key": "aad9132445d6d8f8dda38d7d7634a90754e4ade4db7f3a5ed5d74c2b688823a2",
        }
        account1 = NeonAccount.from_dict(raw_dict)
        self.assertFalse(account1.is_empty)
        self.assertIsNotNone(account1.private_key)
        self.assertTrue(account1.chain_id, int(raw_dict["chain_id"], 16))

        account2 = NeonAccount.from_dict(account1)
        self.assertIs(account2, account1)

        raw_dict2 = {
            "private_key": "0x" + raw_dict["private_key"],
            "chain_id": raw_dict["chain_id"],
            "address": "0x" + raw_dict["address"],
        }
        account3 = NeonAccount.from_dict(raw_dict2)
        self.assertEqual(account3.to_address(), account1.to_address())
        self.assertEqual(account3.to_checksum_address(), account1.to_checksum_address())

        raw_dict.pop("private_key")
        account4 = NeonAccount.from_dict(raw_dict)
        with self.assertRaises(AssertionError):
            _ = account4.private_key

        raw_dict5 = dict()
        account5 = NeonAccount.from_dict(raw_dict5)
        self.assertTrue(account5.is_empty)
        self.assertEqual(account5.to_address(), account5.NullAddress)

    def test_from_raw(self):
        public_key = eth_keys.keys.PrivateKey(bytes(32)).public_key
        account1 = NeonAccount.from_raw(public_key, 10)
        self.assertFalse(account1.is_empty)

        account2 = NeonAccount.from_raw(account1, account1.chain_id)
        self.assertIs(account1, account2)

        account3 = NeonAccount.from_raw(account1, account1.chain_id + 1)
        self.assertIsNot(account1, account3)

        account4 = NeonAccount.from_raw("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f", 12)
        self.assertFalse(account4.is_empty)

        account5 = NeonAccount.from_raw(hex_to_bytes("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f"), 13)
        self.assertFalse(account5.is_empty)

        account6 = NeonAccount.from_raw(bytearray(hex_to_bytes("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f")), 14)
        self.assertFalse(account6.is_empty)

        # wrong size
        with self.assertRaises(ValueError):
            _ = NeonAccount.from_raw("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f12", 15)

        with self.assertRaises(ValueError):
            _ = NeonAccount.from_raw("0xde30da39c46104798bb5aa3fe8b9e0e1f34816", 16)

        with self.assertRaises(ValueError):
            _ = NeonAccount.from_raw(hex_to_bytes("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f12"), 17)

        with self.assertRaises(ValueError):
            _ = NeonAccount.from_raw(hex_to_bytes("0xde30da39c46104798bb5aa3fe8b9e0e1f34816"), 18)

        # wrong type
        with self.assertRaises(ValueError):
            _ = NeonAccount.from_raw(1234, 1234)

    def test_random(self):
        account = NeonAccount.random(12)
        self.assertFalse(account.is_empty)
        self.assertIsNotNone(account.private_key)

    def test_from_private_key(self):
        private_key = bytes(32)
        account = NeonAccount.from_private_key(private_key, 12)
        self.assertFalse(account.is_empty)
        self.assertIsNotNone(account.private_key)

    def test_to_dict(self):
        account1 = NeonAccount.random(12)
        account1_dict = account1.to_dict()
        self.assertIsInstance(account1_dict, dict)
        self.assertTrue("chain_id" in account1_dict)
        self.assertEqual(hex(account1.chain_id), account1_dict["chain_id"])
        self.assertTrue("address" in account1_dict)
        self.assertEqual(account1_dict["address"], account1.to_checksum_address())
        self.assertTrue("private_key" in account1_dict)

        account2 = NeonAccount.from_raw("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f", 14)
        account2_dict = account2.to_dict()
        self.assertIsInstance(account2_dict, dict)
        self.assertTrue("chain_id" in account2_dict)
        self.assertEqual(account2.chain_id, int(account2_dict["chain_id"], 16))
        self.assertTrue("address" in account2_dict)
        self.assertEqual(account2_dict["address"], account2.to_checksum_address())
        self.assertFalse("private_key" in account2_dict)

    def test_is_empty(self):
        account1 = NeonAccount.from_raw(b"\0" * 20, 12)
        self.assertFalse(account1.is_empty)
        self.assertEqual(account1.to_address(), "0x" + "00" * 20)
        self.assertEqual(account1.to_checksum_address(), "0x" + "00" * 20)

        account2 = NeonAccount.from_raw(None, 14)
        self.assertTrue(account2.is_empty)
        self.assertEqual(account2.to_address(), account2.NullAddress)
        self.assertEqual(account2.to_checksum_address(), account2.NullAddress)

        account3 = NeonAccount.from_raw(bytes(), 15)
        self.assertTrue(account3.is_empty)
        self.assertEqual(account3.to_address(), account3.NullAddress)
        self.assertEqual(account3.to_checksum_address(), account3.NullAddress)

        neon_account = NeonAccount.default()
        self.assertTrue(neon_account.is_empty)
        self.assertEqual(neon_account.to_address(), NeonAccount.NullAddress)
        self.assertEqual(neon_account.chain_id, 0)
        self.assertEqual(neon_account._private_key, None)

    def test_to_bytes(self):
        account1 = NeonAccount.random(26)
        self.assertIsNotNone(account1.to_bytes())
        self.assertIsInstance(account1.to_bytes(), bytes)
        self.assertIsNotNone(account1.to_bytes(None))

        account2 = NeonAccount.from_raw(None, 67)
        self.assertIsNotNone(account2.to_bytes())
        self.assertEqual(len(account2.to_bytes()), 0)
        self.assertIsInstance(account2.to_bytes(), bytes)
        self.assertIsNone(account2.to_bytes(None))

    def test_to_address(self):
        account1 = NeonAccount.random(45)
        self.assertIsNotNone(account1.to_address())
        self.assertIsInstance(account1.to_address(), str)
        self.assertIsNotNone(account1.to_address(None))

        account2 = NeonAccount.from_raw(None, 76)
        self.assertIsNotNone(account2.to_address())
        self.assertEqual(account2.to_string(), "")
        self.assertEqual(account2.to_address(), account2.NullAddress)
        self.assertIsNone(account2.to_address(None))

    def test_to_checksum_address(self):
        account1 = NeonAccount.from_private_key(bytes(32), 88)
        self.assertFalse(account1.is_empty)
        self.assertNotEqual(account1.to_checksum_address(), account1.NullAddress)
        self.assertNotEqual(account1.to_string(), "")
        self.assertIsNotNone(account1.private_key)

        account2 = NeonAccount.from_private_key(bytes(33), 99)
        self.assertFalse(account2.is_empty)
        self.assertNotEqual(account2.to_string(), "")
        self.assertNotEqual(account2.to_checksum_address(), account2.NullAddress)
        self.assertIsNotNone(account2.private_key)

        with self.assertRaises(ValueError):
            _ = NeonAccount.from_private_key(bytes(31), 101)

    def test_equal(self):
        account1 = NeonAccount.random(124)
        account2 = NeonAccount.random(124)
        self.assertNotEqual(account1, account2)

    def test_pydantic(self):
        class TestPydanticModel(BaseModel):
            account: NeonAccountField

        src1_model = TestPydanticModel(account=NeonAccount.random(12))
        src1_dump = src1_model.model_dump(mode="json")
        self.assertTrue("account" in src1_dump)
        self.assertTrue("address" in src1_dump["account"])
        self.assertTrue("chain_id" in src1_dump["account"])
        self.assertTrue("private_key" in src1_dump["account"])
        dst1_model = TestPydanticModel.model_validate(src1_dump)

        self.assertIsNotNone(src1_model.account.to_address())
        self.assertIsNotNone(dst1_model.account.to_address())
        self.assertEqual(src1_model.account.to_checksum_address(), dst1_model.account.to_checksum_address())

        src2_model = TestPydanticModel(account=NeonAccount.from_raw("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f", 1))
        src2_dump = src2_model.model_dump(mode="json")
        self.assertTrue("account" in src2_dump)
        self.assertTrue("address" in src2_dump["account"])
        self.assertTrue("chain_id" in src2_dump["account"])
        self.assertFalse("private_key" in src2_dump["account"])
        dst2_model = TestPydanticModel.model_validate(src2_dump)

        self.assertIsNotNone(src2_model.account.to_address())
        self.assertIsNotNone(dst2_model.account.to_address())
        self.assertEqual(src2_model.account.to_checksum_address(), dst2_model.account.to_checksum_address())

        with self.assertRaises(AssertionError):
            _ = dst2_model.account.private_key

    def test_str(self):
        account1 = NeonAccount.random(12)
        account2 = NeonAccount.from_raw(account1, 16)
        self.assertNotEqual(str(account1), str(account2))
        self.assertNotEqual(str(account1), account1.to_address())
        self.assertEqual(str(account1), account1.to_checksum_address() + ":" + hex(account1.chain_id))
        self.assertEqual(str(account1), account1.to_string())

    def test_hash(self):
        account1 = NeonAccount.random(15)
        account2 = NeonAccount.from_raw(account1, 16)
        self.assertEqual(account1.to_address(), account2.to_address())
        self.assertEqual(account1.to_checksum_address(), account2.to_checksum_address())
        self.assertIsNot(account1, account2)
        self.assertNotEqual(account1, account2)
        self.assertNotEqual(hash(account1), hash(account2))

        account3 = NeonAccount.from_raw(account1.to_address(), account1.chain_id)
        self.assertEqual(account1, account3)
        self.assertEqual(hash(account1), hash(account3))


if __name__ == "__main__":
    unittest.main()

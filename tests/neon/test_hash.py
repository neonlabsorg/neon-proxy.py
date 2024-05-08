import unittest

from pydantic import BaseModel

from common.ethereum.hash import EthAddress, EthAddressField, EthHash32, EthHash32Field


class TestNeonHash(unittest.TestCase):
    def test_account_address(self):
        empty_hash = EthAddress.default()
        self.assertEqual(empty_hash.hash_size, 20)
        self.assertTrue(empty_hash.is_empty)
        self.assertEqual(len(empty_hash.to_bytes()), 0)
        self.assertIsNone(empty_hash.to_string())
        self.assertEqual(empty_hash.to_string("0x0"), "0x0")

        with self.assertRaises(ValueError):
            EthAddress.from_raw("0x010203040506")

        with self.assertRaises(ValueError):
            EthAddress.from_raw(b"\0x1\0x2")

        good_hash = EthAddress.from_raw("0x0102030405060708091011121314151617181920")
        self.assertFalse(good_hash.is_empty)
        self.assertIsNotNone(good_hash.to_string())
        self.assertEqual(len(good_hash.to_string()), 42)
        self.assertEqual(len(good_hash.to_bytes()), good_hash.hash_size)
        self.assertNotEqual(good_hash.to_string("0x"), "0x")
        self.assertEqual(good_hash.to_string(), "0x0102030405060708091011121314151617181920")
        self.assertEqual(good_hash.to_string("0x1"), "0x0102030405060708091011121314151617181920")
        self.assertEqual(
            good_hash.to_bytes(), b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20"
        )

    def test_pydantic_account_address(self):
        class TestHash20(BaseModel):
            value: EthAddressField

        test_json = {"value": "0x0102030405060708091011121314151617181920"}
        test_model = TestHash20.model_validate(test_json)
        self.assertEqual(
            test_model.value.to_bytes(),
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20",
        )
        self.assertEqual(test_model.value.to_string(), test_json["value"])

    def test_hash32(self):
        empty_hash = EthHash32.default()
        self.assertEqual(empty_hash.hash_size, 32)
        self.assertTrue(empty_hash.is_empty)
        self.assertEqual(len(empty_hash.to_bytes()), 0)
        self.assertIsNone(empty_hash.to_string())
        self.assertEqual(empty_hash.to_string("0x1"), "0x1")

        with self.assertRaises(ValueError):
            EthHash32.from_raw(b"\0x1\0x2")

        with self.assertRaises(ValueError):
            EthHash32.from_raw("0x010203040506")

        good_hash = EthHash32.from_raw("0x0102030405060708091011121314151617181920212223242526272829303132")
        self.assertFalse(good_hash.is_empty)
        self.assertIsNotNone(good_hash.to_string())
        self.assertEqual(len(good_hash.to_string()), 66)
        self.assertEqual(len(good_hash.to_bytes()), good_hash.hash_size)
        self.assertNotEqual(good_hash.to_string("0x2"), "0x2")
        self.assertEqual(good_hash.to_string(), "0x0102030405060708091011121314151617181920212223242526272829303132")
        self.assertEqual(
            good_hash.to_string("0x3"), "0x0102030405060708091011121314151617181920212223242526272829303132"
        )
        self.assertEqual(
            good_hash.to_bytes(),
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32",
        )

    def test_pydantic_hash32(self):
        class TestHash32(BaseModel):
            value: EthHash32Field

        test_json = {"value": "0x0102030405060708091011121314151617181920212223242526272829303132"}
        test_model = TestHash32.model_validate(test_json)
        self.assertEqual(
            test_model.value.to_bytes(),
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32",
        )
        self.assertEqual(test_model.value.to_string(), test_json["value"])


if __name__ == "__main__":
    unittest.main()

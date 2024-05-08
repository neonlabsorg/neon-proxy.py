import unittest
from pydantic import BaseModel
from common.ethereum.bin_str import EthBinStr, EthBinStrField
from common.utils.format import bytes_to_hex
from common.utils.pydantic import BaseModel


class TestEthBinStr(unittest.TestCase):

    def test_init(self):
        with self.assertRaises(ValueError):
            EthBinStr("not_bytes")  # noqa

        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str._data, b"bytes")

    def test_from_raw(self):
        raw = "0x123456"
        neon_bin_str = EthBinStr.from_raw(raw)
        self.assertEqual(neon_bin_str._data, b"\x12\x34\x56")

        raw = EthBinStr(b"bytes")
        neon_bin_str_2 = EthBinStr.from_raw(raw)
        self.assertEqual(neon_bin_str_2._data, b"bytes")

        raw = bytearray(b"bytes")
        neon_bin_str_3 = EthBinStr.from_raw(raw)
        self.assertEqual(neon_bin_str_3._data, b"bytes")

        raw = b"bytes"
        neon_bin_str_4 = EthBinStr.from_raw(raw)
        self.assertEqual(neon_bin_str_4._data, b"bytes")

    def test_default(self):
        neon_bin_str = EthBinStr.default()
        self.assertEqual(neon_bin_str._data, bytes())

    def test_is_empty(self):
        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str.is_empty, False)

        neon_bin_str_empty = EthBinStr(bytes())
        self.assertEqual(neon_bin_str_empty.is_empty, True)

    def test_to_string(self):
        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str.to_string(), bytes_to_hex(b"bytes"))

        neon_bin_str_empty = EthBinStr(bytes())
        self.assertEqual(neon_bin_str_empty.to_string(), "0x")

    def test_to_bytes(self):
        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str.to_bytes(), b"bytes")

    def test_str(self):
        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str.to_string(), bytes_to_hex(b"bytes"))

    def test_repr(self):
        neon_bin_str = EthBinStr(b"bytes")
        self.assertEqual(neon_bin_str.to_string(), bytes_to_hex(b"bytes"))

    def test_model(self):
        class TestBinStrModel(BaseModel):
            value: EthBinStrField

        null_json = {"value": None}
        null_model = TestBinStrModel.model_validate(null_json)
        self.assertEqual(null_model.value, "0x")

        empty_json = {"value": ""}
        empty_model = TestBinStrModel.model_validate(empty_json)
        self.assertEqual(empty_model.value, "0x")

        zero_json = {"value": "0X"}
        zero_model = TestBinStrModel.model_validate(zero_json)
        self.assertEqual(zero_model.value, "0x")

        no_prefix_json = {"value": "1257034051254554223abfcde20556"}
        no_prefix_model = TestBinStrModel.model_validate(no_prefix_json)
        self.assertEqual(no_prefix_model.value, "0x1257034051254554223abfcde20556")

        full_json = {"value": "0xabfedc1252dec1"}
        full_model = TestBinStrModel.model_validate(full_json)
        self.assertEqual(full_model.value, "0xabfedc1252dec1")

        bytes_json = {"value": b"\x01\x02\x03\x04\x05\x06\x07"}
        bytes_model = TestBinStrModel.model_validate(bytes_json)
        self.assertEqual(bytes_model.value, "0x01020304050607")

        with self.assertRaises(ValueError):
            error_json = {"value": "0xsa91qg58520dfnbq909qgg124"}
            TestBinStrModel.model_validate(error_json)

        with self.assertRaises(ValueError):
            error_json = {"value": "0xabc"}
            TestBinStrModel.model_validate(error_json)

        with self.assertRaises(ValueError):
            bytes_json = {"value": 12345}
            TestBinStrModel.model_validate(bytes_json)


if __name__ == "__main__":
    unittest.main()

import unittest

from common.utils.pydantic import HexUIntField, NullIntField, DecIntField, BytesField, BaseModel


class TestPydantic(unittest.TestCase):
    def test_hex_int_field(self):
        class TestHexIntModel(BaseModel):
            value: HexUIntField

        null_json = {"value": None}
        null_model = TestHexIntModel.model_validate(null_json)
        self.assertIsNone(null_model.value)

        zero_json = {"value": "0x"}
        zero_model = TestHexIntModel.model_validate(zero_json)
        self.assertEqual(zero_model.value, 0)

        zero_json1 = {"value": "0X"}
        zero_model1 = TestHexIntModel.model_validate(zero_json1)
        self.assertEqual(zero_model1.value, 0)

        no_prefix_json = {"value": "ab"}
        no_prefix_model = TestHexIntModel.model_validate(no_prefix_json)
        self.assertEqual(no_prefix_model.value, 171)

        full_json = {"value": "0xcd"}
        full_model = TestHexIntModel.model_validate(full_json)
        self.assertEqual(full_model.value, 205)

        with self.assertRaises(ValueError):
            error_json = {"value": "0x1541523hasoei14"}
            TestHexIntModel.model_validate(error_json)

        test_model = TestHexIntModel(value=1)
        test_json = test_model.model_dump(mode="json")
        self.assertEqual(test_json["value"], "0x1")

    def test_null_int_field(self):
        class TestNullIntModel(BaseModel):
            value: NullIntField

        null_json = {"value": None}
        null_model = TestNullIntModel.model_validate(null_json)
        self.assertEqual(null_model.value, 0)

        zero_json = {"value": 0}
        zero_model = TestNullIntModel.model_validate(zero_json)
        self.assertEqual(zero_model.value, 0)

        full_json = {"value": 125}
        full_model = TestNullIntModel.model_validate(full_json)
        self.assertEqual(full_model.value, 125)

        with self.assertRaises(ValueError):
            error_json = {"value": "helloworld"}
            TestNullIntModel.model_validate(error_json)

    def test_dec_int_field(self):
        class TestDecInt(BaseModel):
            value: DecIntField

        null_json = {"value": None}
        null_model = TestDecInt.model_validate(null_json)
        self.assertEqual(null_model.value, 0)

        full_json = {"value": 125}
        full_model = TestDecInt.model_validate(full_json)
        self.assertEqual(full_model.value, 125)

        str_json = {"value": "125"}
        str_model = TestDecInt.model_validate(full_json)
        self.assertEqual(str_model.value, 125)

        with self.assertRaises(ValueError):
            error_json = {"value": "helloworld"}
            TestDecInt.model_validate(error_json)

    def test_bytes_field(self):
        class TestBytes(BaseModel):
            value: BytesField

        null_json = {"value": None}
        null_model = TestBytes.model_validate(null_json)
        self.assertEqual(null_model.value, bytes())

        str_json = {"value": "125"}
        str_model = TestBytes.model_validate(str_json)
        self.assertEqual(str_model.value, b"125")

        bytes_json = {"value": b"125"}
        bytes_model = TestBytes.model_validate(bytes_json)
        self.assertEqual(bytes_model.value, b"125")

        bytearray_json = {"value": bytearray(b"125")}
        bytearray_model = TestBytes.model_validate(bytes_json)
        self.assertEqual(bytearray_model.value, b"125")

        with self.assertRaises(ValueError):
            error_json = {"value": 1255}
            TestBytes.model_validate(error_json)

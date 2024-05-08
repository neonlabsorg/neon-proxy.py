import unittest

from enum import Enum

from common.utils.format import (
    get_from_dict,
    bytes_to_hex,
    has_hex_start,
    hex_to_int,
    hex_to_bytes,
    u256big_to_hex,
    u256big_to_bytes,
    int_to_enum,
    str_fmt_object,
)


# from ._test_log_bloom import test_tx_log_bloom, test_tx_res_info


class TestGetFromDict(unittest.TestCase):
    def test_get_from_dict(self):
        test_dict = {"a": {"b": {"c": 1}}}

        self.assertEqual(get_from_dict(test_dict, ("a", "b", "c"), None), 1)
        self.assertEqual(get_from_dict(test_dict, ("a",), None), {"b": {"c": 1}})
        self.assertIsNone(get_from_dict(test_dict, ("b", "c", "a"), None))

        test_dict_list = {"a": {"b": [10, 20]}}
        self.assertEqual(get_from_dict(test_dict_list, ("a", "b", 0), -1), 10)
        self.assertEqual(get_from_dict(test_dict_list, ("a", "b", 2), -1), -1)
        self.assertEqual(get_from_dict(test_dict_list, ("a", "b", -1), -1), -1)

        self.assertIsNone(get_from_dict(None, ("a",), None))
        self.assertIsNone(get_from_dict(555, ("a",), None))  # noqa
        self.assertIsNone(get_from_dict("555", ("a",), None))  # noqa
        self.assertIsNone(get_from_dict({}, ("a",), None))

    #
    # def test_log_bloom(self):
    #     self.assertEqual(
    #         test_tx_res_info.log_bloom,
    #         int(test_tx_log_bloom[2:], 16)
    #     )
    #     self.assertEqual(
    #         u256big_to_hex(test_tx_res_info.log_bloom),
    #         test_tx_log_bloom
    #     )


class TestBytesToHex(unittest.TestCase):

    def test_none_input(self):
        self.assertEqual(bytes_to_hex(None), "0x")

    def test_empty_string_input(self):
        self.assertEqual(bytes_to_hex(""), "0x")

    def test_string_representation_of_bytes_input(self):
        # assuming the hex_to_bytes function returns a bytes object
        self.assertEqual(bytes_to_hex("68656c6c6f"), "0x68656c6c6f")

    def test_bytes_input(self):
        self.assertEqual(bytes_to_hex(b"hello"), "0x68656c6c6f")

    def test_bytearray_input(self):
        self.assertEqual(bytes_to_hex(bytearray(b"hello")), "0x68656c6c6f")

    def test_with_different_prefix(self):
        self.assertEqual(bytes_to_hex(b"hello", prefix="0b"), "0b68656c6c6f")

    def test_invalid_value_type(self):
        with self.assertRaises(AttributeError):
            bytes_to_hex(123456)  # noqa


class TestHelpers(unittest.TestCase):

    def test_has_hex_start_with_hex_value(self):
        self.assertTrue(has_hex_start("0xabc123"))

    def test_has_hex_start_with_uppercase_hex_value(self):
        self.assertTrue(has_hex_start("0Xabc123"))

    def test_has_hex_start_with_no_hex_symbol(self):
        self.assertFalse(has_hex_start("abc123"))

    def test_has_hex_start_with_non_string_value(self):
        self.assertFalse(has_hex_start(123))  # noqa

    def test_has_hex_start_with_empty_string(self):
        self.assertFalse(has_hex_start(""))


class TestHexToInt(unittest.TestCase):
    def test_hex_to_int(self):
        self.assertEqual(hex_to_int("1"), 1)
        self.assertEqual(hex_to_int("a"), 10)
        self.assertEqual(hex_to_int("f"), 15)
        self.assertEqual(hex_to_int("10"), 16)
        self.assertEqual(hex_to_int("1a"), 26)
        self.assertEqual(hex_to_int("ff"), 255)

    def test_hex_to_int_invalid_input(self):
        with self.assertRaises(ValueError):
            hex_to_int("g")


class TestHexToBytes(unittest.TestCase):
    def test_hex_to_bytes_with_None(self):
        self.assertEqual(hex_to_bytes(None), bytes())

    def test_hex_to_bytes_with_empty_str(self):
        self.assertEqual(hex_to_bytes(""), bytes())

    def test_hex_to_bytes_with_bytes_input(self):
        self.assertEqual(hex_to_bytes(b"ab"), b"ab")

    def test_hex_to_bytes_with_bytearray_input(self):
        self.assertEqual(hex_to_bytes(bytearray(b"ab")), b"ab")

    def test_hex_to_bytes_with_hex_str(self):
        self.assertEqual(hex_to_bytes("0x6162"), b"ab")

    def test_hex_to_bytes_with_hex_str_no_prefix(self):
        self.assertEqual(hex_to_bytes("6162"), b"ab")

    def test_hex_to_bytes_with_nonhex_str(self):
        with self.assertRaises(ValueError):
            hex_to_bytes("GX")


class TestU256ToHex(unittest.TestCase):
    _U256_LENGTH = 256 * 2 + 2

    def test_u256big_to_hex(self):
        # This is an example value, replace with your own value
        sample_value = 12345
        result = u256big_to_hex(sample_value)

        # Verify the result is as expected
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("0x"))
        self.assertEqual(hex_to_int(result), sample_value)
        self.assertEqual(len(result), self._U256_LENGTH)

    def test_big_value(self):
        sample_value = 2**256 - 1
        self.assertEqual(len(u256big_to_hex(sample_value)), self._U256_LENGTH)

        sample_value = 2**256 + 1
        self.assertEqual(len(u256big_to_hex(sample_value)), self._U256_LENGTH)


class TestU256bigToBytes(unittest.TestCase):
    _U256_LENGTH = 256

    def test_positive_integers(self):
        # Test with some positive integers
        sample_value = 1234
        self.assertEqual(
            u256big_to_bytes(sample_value), sample_value.to_bytes(256, "big")
        )
        self.assertEqual(len(u256big_to_bytes(sample_value)), self._U256_LENGTH)

        sample_value = 5678
        self.assertEqual(len(u256big_to_bytes(sample_value)), self._U256_LENGTH)
        self.assertEqual(
            u256big_to_bytes(sample_value), sample_value.to_bytes(256, "big")
        )

    def test_zero_value(self):
        # Test with 0
        sample_value = 0
        self.assertEqual(len(u256big_to_bytes(sample_value)), self._U256_LENGTH)
        self.assertEqual(
            u256big_to_bytes(sample_value), sample_value.to_bytes(256, "big")
        )

    def test_large_values(self):
        # Test with some large values
        large_value1 = 2**200
        self.assertEqual(
            u256big_to_bytes(large_value1), large_value1.to_bytes(256, "big")
        )
        self.assertEqual(len(u256big_to_bytes(large_value1)), self._U256_LENGTH)

        large_value2 = 2**255 - 1
        self.assertEqual(
            u256big_to_bytes(large_value2), large_value2.to_bytes(256, "big")
        )
        self.assertEqual(len(u256big_to_bytes(large_value2)), self._U256_LENGTH)

        large_value3 = 2**512
        self.assertEqual(len(u256big_to_bytes(large_value3)), self._U256_LENGTH)


class TestEnumToInt(unittest.TestCase):
    class TestEnum(Enum):
        A = 1
        B = 2
        C = 3
        D = 4

    def test_int_to_enum_valid_value(self):
        self.assertEqual(int_to_enum(self.TestEnum, 2), "B")

    def test_int_to_enum_invalid_value(self):
        self.assertEqual(int_to_enum(self.TestEnum, 0), "0x0")

    def test_int_to_enum_max_value(self):
        self.assertEqual(int_to_enum(self.TestEnum, 4), "D")

    def test_int_to_enum_min_value(self):
        self.assertEqual(int_to_enum(self.TestEnum, 1), "A")


LOG_FULL_OBJECT_INFO = False


class TestStrFmtObject(unittest.TestCase):
    def test_str_fmt_object_with_none(self):
        self.assertEqual(str_fmt_object(None), "None")

    def test_str_fmt_object_with_string(self):
        test_str = "Hello, world!"
        self.assertEqual(str_fmt_object(test_str), "'" + test_str + "'")

    def test_str_fmt_object_with_bytes(self):
        test_bytes = b"Hello, world!"
        self.assertEqual(str_fmt_object(test_bytes), "'48656c6c6f2c20776f72...'")

    def test_str_fmt_object_with_list(self):
        test_list = [1, 2, 3, 4, 5]
        self.assertEqual(str_fmt_object(test_list), "list(len=5, [...])")

    def test_str_fmt_object_with_dict(self):
        test_dict = {"key1": "value1", "key2": "value2"}
        self.assertEqual(
            str_fmt_object(test_dict), "dict(key1='value1', key2='value2')"
        )

    def test_str_fmt_object_with_custom_object(self):
        class TestNestedClass(object):
            def __init__(self, param):
                self.param = param

            def __str__(self):
                return str_fmt_object(self)

        class TestClass:
            def __init__(self, param1, param2):
                self.param1 = param1
                self.param2 = param2
                self.param3 = TestNestedClass([param1, param2])
                self.param4 = TestNestedClass({param1: param2})

            def __str__(self):
                return str_fmt_object(self)

        test_obj = TestClass("hello", "world")

        self.assertEqual(
            (
                "TestClass("
                "param1='hello', "
                "param2='world', "
                "param3=TestNestedClass(param=list(len=2, [...])), "
                "param4=TestNestedClass(param=dict(hello='world'))"
                ")"
            ),
            str(test_obj),
        )


if __name__ == "__main__":
    unittest.main()

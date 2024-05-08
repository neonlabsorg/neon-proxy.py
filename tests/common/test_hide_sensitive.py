import unittest
from common.config.config import Config
from common.config.utils import hide_sensitive_info, LogMsgFilter


class HideSensitiveInfoTestCase(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.msg_filter = LogMsgFilter(self.config)

    def test_with_none_input(self):
        val = hide_sensitive_info(self.msg_filter, None)  # noqa
        self.assertIsNone(val)

    def test_with_wrong_input_type(self):
        val = hide_sensitive_info(self.msg_filter, 12345)  # noqa
        self.assertEqual(val, 12345)

    def test_without_hiding_info(self):
        val = hide_sensitive_info(self.msg_filter, "test_string")
        self.assertEqual(val, "test_string")

    def test_hiding_info_in_str(self):
        for item in self.config.sensitive_info_list:
            in_value = "Hello " + item + ", it is nice to see you"
            out_value = hide_sensitive_info(self.msg_filter, in_value)
            self.assertEqual(out_value, "Hello *****, it is nice to see you")

    def test_hiding_info_in_list(self):
        in_value_list = [
            "Hello " + item + ", it is nice to see you"
            for item in self.config.sensitive_info_list
        ]
        out_value_list = hide_sensitive_info(self.msg_filter, in_value_list)
        for out_value in out_value_list:
            self.assertEqual(out_value, "Hello *****, it is nice to see you")


if __name__ == "__main__":
    unittest.main()

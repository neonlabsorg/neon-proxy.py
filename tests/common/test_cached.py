import unittest
from dataclasses import dataclass

from common.utils.cached import reset_cached_property, reset_cached_method, CachedObject


class TestCachedValue(unittest.TestCase):
    class _CachedValue(CachedObject):
        def __init__(self, value: int):
            self._value = value
            self._second_value = value

        @reset_cached_method
        def get_value(self) -> int:
            self._value += 1
            return self._value

        @reset_cached_property
        def value(self) -> int:
            self._value += 1
            return self._value

    @dataclass(frozen=True)
    class _CachedDataclass(CachedObject):
        base_value: int

        @reset_cached_property
        def value(self) -> int:
            value = self.base_value + 1
            object.__setattr__(self, "base_value", value)
            return value

    def test_cached_method(self):
        test_m1 = self._CachedValue(10)
        for i in range(5):
            self.assertEqual(test_m1.get_value(), 11)

        test_m2 = self._CachedValue(21)
        self.assertEqual(test_m2.get_value(), 22)

        test_m1.get_value.reset_cache(test_m1)
        for i in range(5):
            self.assertEqual(test_m1.get_value(), 12)

        self.assertEqual(test_m2.get_value(), 22)
        test_m2.reset_cache("get_value")
        for i in range(5):
            self.assertEqual(test_m2.get_value(), 23)

    def test_cached_property(self):
        test_v1 = self._CachedValue(30)
        for i in range(5):
            self.assertEqual(test_v1.value, 31)

        test_v2 = self._CachedValue(41)
        self.assertEqual(test_v2.value, 42)

        test_v1.reset_cache("value")
        for i in range(5):
            self.assertEqual(test_v1.value, 32)

        self.assertEqual(test_v2.value, 42)
        test_v2.reset_cache("value")
        for i in range(5):
            self.assertEqual(test_v2.value, 43)

    def test_cached_dataclass(self):
        test_v1 = self._CachedDataclass(50)
        for i in range(5):
            self.assertEqual(test_v1.value, 51)

        test_v2 = self._CachedDataclass(61)
        self.assertEqual(test_v2.value, 62)

        test_v1.reset_cache("value")
        for i in range(5):
            self.assertEqual(test_v1.value, 52)

        self.assertEqual(test_v2.value, 62)
        test_v2.reset_cache("value")
        for i in range(5):
            self.assertEqual(test_v2.value, 63)


if __name__ == "__main__":
    unittest.main()

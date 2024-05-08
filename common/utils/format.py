from __future__ import annotations

import os
from enum import Enum

# fmt: off
_LOG_FULL_OBJECT_INFO = os.environ.get("LOG_FULL_OBJECT_INFO", "NO").upper() in (
    "YES", "ON", "TRUE", "1",
)
_LOG_OBJECT_INFO_LIMIT = int(os.environ.get("LOG_OBJECT_INFO_LIMIT", str(2**64)))
# fmt: on


def str_fmt_object(obj, skip_underscore_prefix=True, name="") -> str:
    def _decode_name(value) -> str:
        return type(value).__name__

    def _lookup_dict_as_value(value_type: str, value: dict) -> tuple[bool, str]:
        result = _lookup_dict(value)
        if (not _LOG_FULL_OBJECT_INFO) and (not result):
            return False, "?"

        return True, value_type + "(" + result + ")"

    def _lookup_str_as_value(value: str | bytes | bytearray) -> tuple[bool, str]:
        if (not _LOG_FULL_OBJECT_INFO) and (not value):
            return False, "?"

        if not isinstance(value, str):
            value = value.hex()
        if (not _LOG_FULL_OBJECT_INFO) and (value[:2] in ("0x", "0X")):
            value = value[2:]
        if (not _LOG_FULL_OBJECT_INFO) and (len(value) > 20):
            value = value[:20] + "..."
        return True, "'" + value + "'"

    def _lookup_list_as_value(value_list_type: str, value_list: set | list) -> tuple[bool, str]:
        if _LOG_FULL_OBJECT_INFO:
            result = ""
            for item in value_list:
                has_item, item = _decode_value(item)
                if result:
                    result += ", "
                result += item if has_item else "?..."
            return True, value_list_type + "([" + result + "])"

        elif not value_list:
            return False, "?"

        return True, value_list_type + "(len=" + str(len(value_list)) + ", [...])"

    def _decode_value(value) -> tuple[bool, str]:
        if callable(value):
            if _LOG_FULL_OBJECT_INFO:
                return True, "callable(...)"
        elif value is None:
            if _LOG_FULL_OBJECT_INFO:
                return True, "None"
        elif isinstance(value, bool):
            if value or _LOG_FULL_OBJECT_INFO:
                return True, str(value)
        elif isinstance(value, Enum):
            return True, value.name
        elif isinstance(value, list):
            return _lookup_list_as_value("list", value)
        elif isinstance(value, set):
            return _lookup_list_as_value("set", value)
        elif isinstance(value, str) or isinstance(value, bytes) or isinstance(value, bytearray):
            return _lookup_str_as_value(value)
        elif isinstance(value, dict):
            return _lookup_dict_as_value("dict", value)
        elif hasattr(value, "__str__"):
            value = str(value)
            if _LOG_FULL_OBJECT_INFO or len(value):
                return True, value
        elif hasattr(value, "__dict__"):
            return _lookup_dict_as_value(_decode_name(value), value.__dict__)
        return False, "?"

    def _lookup_dict(d: dict) -> str:
        idx = 0
        result = ""
        for key, value in d.items():
            if not isinstance(key, str):
                key = str(key)
            if skip_underscore_prefix and key.startswith("_"):
                continue

            has_value, value = _decode_value(value)
            if not has_value:
                continue

            if idx > 0:
                result += ", "
            result += key.strip("_") + "=" + value
            idx += 1
            if (not _LOG_FULL_OBJECT_INFO) and (idx >= _LOG_OBJECT_INFO_LIMIT):
                break
        return result

    if obj is None:
        return "None"

    if not name:
        name = _decode_name(obj)

    if hasattr(obj, "__dict__"):
        content = _lookup_dict(obj.__dict__)
    elif isinstance(obj, dict):
        content = _lookup_dict(obj)
    else:
        _flag, content = _decode_value(obj)
        return content

    return name + "(" + content + ")"


def get_from_dict(src: dict | list | None, path: tuple, default_value):
    """Provides smart getting values from python dictionary"""
    value = src
    for key in path:
        if isinstance(value, list) and isinstance(key, int) and (0 <= key < len(value)):
            return value[key]

        if not isinstance(value, dict):
            return default_value

        value = value.get(key, None)
        if value is None:
            return default_value
    return value


def int_to_enum(cls, value: int):
    try:
        return cls(value).name
    except ValueError:
        return hex(value)


def u256big_to_bytes(value: int) -> bytes:
    return value.to_bytes(256, "big")


def u256big_to_hex(value: int, prefix: str = "0x") -> str:
    return prefix + u256big_to_bytes(value).hex()


def hex_to_bytes(value: str | bytes | bytearray | None, default: bytes | None = bytes()) -> bytes | None:
    if not value:
        return default
    elif isinstance(value, bytes):
        return value
    elif isinstance(value, bytearray):
        return bytes(value)
    elif not isinstance(value, str):
        raise ValueError(f"Wrong input type {type(value).__name__}")

    if has_hex_start(value):
        value = value[2:]
    result = bytes.fromhex(value)
    if len(result) * 2 != len(value):
        raise ValueError(f"Input has wrong length {len(value)}")

    return result


def bytes_to_hex(value: str | bytes | bytearray | None, prefix: str = "0x") -> str:
    if not value:
        return prefix

    elif isinstance(value, str):
        value = hex_to_bytes(value)

    return prefix + value.hex()


def has_hex_start(value: str) -> bool:
    return isinstance(value, str) and value[:2] in ("0x", "0X")


def hex_to_int(value: str) -> int:
    return int(value, 16)

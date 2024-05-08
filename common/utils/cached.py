from __future__ import annotations

import inspect
import time
from dataclasses import dataclass
from typing import Any

from typing_extensions import Self


class CachedObject:
    __cached_value_dict__: dict

    def reset_cache(self, attr_name: str) -> None:
        self.__cached_value_dict__.pop(attr_name, None)


class _CachedValue:
    __cached_value_dict__ = "__cached_value_dict__"

    def __init__(self, func=None) -> None:
        self._is_async = False
        self._func = None
        if func is not None:
            self.__call__(func)

    def __call__(self, func) -> Self:
        self.__doc__ = getattr(func, "__doc__")
        self.__name__ = getattr(func, "__name__")
        self.__module__ = getattr(func, "__module__")
        self._is_async = inspect.iscoroutinefunction(func)
        self._func = func
        return self

    def _get_cached_value_dict(self, obj) -> dict:
        if not hasattr(obj, self.__cached_value_dict__):
            cached_value_dict = obj.__dict__[self.__cached_value_dict__] = dict()
        else:
            cached_value_dict = obj.__dict__[self.__cached_value_dict__]
        return cached_value_dict


class _ResetCachedValue(_CachedValue):
    def reset_cache(self, obj):
        self._get_cached_value_dict(obj).pop(self.__name__, None)


class cached_property(_CachedValue):  # noqa
    def __get__(self, obj, cls):
        if obj is None:
            return self

        value = self._func(obj)
        obj.__dict__[self.__name__] = value
        return value


class cached_method(_CachedValue):  # noqa
    def __get__(self, obj, cls):
        if obj is None:
            return self

        def _wrapper():
            value = self._func(obj)

            def _return_value():
                return value

            obj.__dict__[self.__name__] = _return_value
            return value

        async def _async_wrapper():
            # only one task can change the cached value
            cached_value_dict = self._get_cached_value_dict(obj)
            has_task = self.__name__ in cached_value_dict
            if not has_task:
                cached_value_dict[self.__name__] = True

            try:
                value = await self._func(obj)
            except BaseException:
                if not has_task:
                    cached_value_dict.pop(self.__name__, None)
                raise

            async def _return_value():
                return value

            if not has_task:
                obj.__dict__[self.__name__] = _return_value
            return value

        if self._is_async:
            return _async_wrapper
        return _wrapper


class reset_cached_property(_ResetCachedValue):  # noqa
    def __get__(self, obj, cls):
        if obj is None:
            return self

        cached_value_dict = self._get_cached_value_dict(obj)
        if self.__name__ in cached_value_dict:
            return cached_value_dict[self.__name__]

        value = self._func(obj)
        cached_value_dict[self.__name__] = value
        return value


class reset_cached_method(_ResetCachedValue):  # noqa
    def __get__(self, obj, cls):
        if obj is None:
            return self

        def _wrapper():
            cached_value_dict = self._get_cached_value_dict(obj)
            if self.__name__ in cached_value_dict:
                return cached_value_dict[self.__name__]

            value = self._func(obj)
            cached_value_dict[self.__name__] = value
            return value

        @dataclass(frozen=True)
        class _AsyncCachedValue:
            is_valid: bool
            value: Any

        async def _async_wrapper():
            # only one coroutine can set the cached value
            cached_value_dict = self._get_cached_value_dict(obj)
            cached: _AsyncCachedValue | None = cached_value_dict.get(self.__name__, None)
            if cached:
                if cached.is_valid:
                    return cached.value
            else:
                cached_value_dict[self.__name__] = _AsyncCachedValue(False, None)

            try:
                value = await self._func(obj)
            except BaseException:
                if not cached:
                    cached_value_dict.pop(self.__name__, None)
                raise

            # cache the value
            if not cached:
                cached_value_dict[self.__name__] = _AsyncCachedValue(True, value)
            return value

        if self._is_async:
            setattr(_async_wrapper, "reset_cache", self.reset_cache)
            return _async_wrapper
        setattr(_wrapper, "reset_cache", self.reset_cache)
        return _wrapper


class ttl_cached_method(_ResetCachedValue):  # noqa
    def __init__(self, *, ttl_msec: int = 0, ttl_sec: int = 0, func=None) -> None:
        assert ttl_msec >= 0, "ttl_msec must be greater or equal 0"
        assert ttl_sec >= 0, "ttl_sec must be greater or equal 0"

        ttl_sec *= 1_000
        ttl_msec += ttl_sec
        assert ttl_msec > 0, "ttl_sec.ttl_msec must be greater than 0"

        super().__init__(func)
        self._ttl_nsec = ttl_msec * 1_000_000

    def __get__(self, obj, cls):
        if obj is None:
            return self

        @dataclass(frozen=True)
        class _SyncCachedValue:
            last_updated: int
            value: Any

        def _wrapper():
            now = time.monotonic_ns()
            cached_value_dict = self._get_cached_value_dict(obj)
            cached: _SyncCachedValue | None = cached_value_dict.get(self.__name__, None)
            if cached and (now - cached.last_updated <= self._ttl_nsec):
                return cached.value

            value = self._func(obj)
            now = time.monotonic_ns()  # calculation can be long
            cached_value_dict[self.__name__] = _SyncCachedValue(now, value)
            return value

        @dataclass(frozen=True)
        class _AsyncCachedValue:
            is_valid: bool
            in_progress: bool
            last_updated: int
            value: Any

        async def _async_wrapper():
            # only one task can change the cached value
            now = time.monotonic_ns()
            cached_value_dict = self._get_cached_value_dict(obj)
            cached: _AsyncCachedValue | None = cached_value_dict.get(self.__name__, None)

            if cached:
                # not cached.is_valid
                #     cache doesn't have any value
                #     another coroutine already calculates the value for the cache
                if cached.is_valid:
                    if cached.in_progress or (now - cached.last_updated) <= self._ttl_nsec:
                        # in-progress: another coroutine has already started the calculation of the new value
                        return cached.value
                    # set in-progress=True,
                    #     other coroutines will get old value,
                    #     till this coroutine calculates the new value
                    cached_value_dict[self.__name__] = _AsyncCachedValue(cached.is_valid, True, now, cached.value)
            else:
                # set is-valid=False
                #     this coroutine gets the lock on the calculation of the value
                #     other coroutines calculate the value too
                #     but only this coroutine can set the value in the cache
                # it happens only on the initialization,
                # in other cases other coroutines get an old value,
                # till one of them calculates the new value
                cached_value_dict[self.__name__] = _AsyncCachedValue(False, True, now, None)

            try:
                value = await self._func(obj)
            except BaseException:
                if not cached:
                    cached_value_dict.pop(self.__name__, None)
                elif cached.is_valid:
                    cached_value_dict[self.__name__] = cached
                raise

            # cache the value in 2 cases:
            #   - the first initialization (not cached)
            #   - the replacement of the old value with the new one
            if not cached or cached.is_valid:
                now = time.monotonic_ns()  # the calculation can be long, but now it is a fresh value
                cached_value_dict[self.__name__] = _AsyncCachedValue(True, False, now, value)
            return value

        if self._is_async:
            setattr(_async_wrapper, "reset_cache", self.reset_cache)
            return _async_wrapper
        setattr(_wrapper, "reset_cache", self.reset_cache)
        return _wrapper

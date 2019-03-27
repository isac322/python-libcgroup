# coding: UTF-8

import errno
import os
from ctypes import byref, c_bool, c_char_p, c_int, c_int64, c_uint64, c_void_p, create_string_buffer
from typing import Callable, Iterable, NoReturn, Optional, Type, TypeVar, Union

from libcgroup_bind.error import ErrorCode, cgroup_get_last_errno, cgroup_strerror
from libcgroup_bind.groups import (
    CGroupControllerPointer, cgroup_get_procs, cgroup_get_value_bool, cgroup_get_value_int64, cgroup_get_value_string,
    cgroup_get_value_uint64, cgroup_set_value_bool, cgroup_set_value_int64, cgroup_set_value_string,
    cgroup_set_value_uint64
)
from libcgroup_bind.iterators import (
    MountPoint, c_int_p, cgroup_get_controller_begin, cgroup_get_controller_end, cgroup_get_controller_next,
    cgroup_get_task_begin, cgroup_get_task_end, cgroup_get_task_next, cgroup_read_value_begin, cgroup_read_value_end,
    cgroup_read_value_next
)

_FT = TypeVar('_FT')
_BUFFER_LEN = 64


def _all_controllers() -> Iterable[MountPoint]:
    handler = c_void_p()
    controller = MountPoint()

    try:
        ret = cgroup_get_controller_begin(byref(handler), byref(controller))

        while ret is 0:
            yield controller
            ret = cgroup_get_controller_next(byref(handler), byref(controller))

        if ret != ErrorCode.EOF:
            _raise_error(ret)
    finally:
        ret = cgroup_get_controller_end(byref(handler))
        if ret is not 0:
            _raise_error(ret)


def all_controller_names() -> Iterable[str]:
    for mount_point in _all_controllers():
        yield str(mount_point.name)


def create_c_array(c_type, elements, length=None):
    elements_tup = tuple(elements)
    if length is None:
        length = len(elements_tup)
    return (c_type * length)(*elements_tup)


# for internal


def _raise_error(ret: ErrorCode) -> NoReturn:
    err = cgroup_get_last_errno()
    if err is not 0:
        def_msg = '{}, {}.'.format(errno.errorcode[err], os.strerror(err))
        raise OSError(err, def_msg, cgroup_strerror(ret).decode())
    else:
        raise ValueError(cgroup_strerror(ret).decode())


# reading cgroup parameter

def _get_string_value(controller: CGroupControllerPointer, name: bytes) -> bytes:
    raw_result = c_char_p()
    ret = cgroup_get_value_string(controller, name, byref(raw_result))
    if ret is not 0:
        _raise_error(ret)

    return raw_result.value


def _get_int_value(controller: CGroupControllerPointer, name: bytes) -> int:
    raw_result = c_int64()
    ret = cgroup_get_value_int64(controller, name, byref(raw_result))
    if ret == ErrorCode.INVAL:
        raw_result = c_uint64()
        ret = cgroup_get_value_uint64(controller, name, byref(raw_result))
        if ret is not 0:
            _raise_error(ret)
    elif ret is not 0:
        _raise_error(ret)

    return raw_result.value


def _get_bool_value(controller: CGroupControllerPointer, name: bytes) -> bool:
    raw_result = c_bool()
    ret = cgroup_get_value_bool(controller, name, byref(raw_result))
    if ret is not 0:
        _raise_error(ret)

    return raw_result.value


def _get_from_cached(controller: CGroupControllerPointer,
                     name: bytes,
                     infer_func: Callable[[bytes], _FT],
                     val_type: Optional[Type[_FT]]) -> _FT:
    if val_type is None:
        ret = _get_string_value(controller, name)
        return infer_func(ret)

    elif val_type is str:
        ret = _get_string_value(controller, name)
        return ret.decode()

    elif issubclass(val_type, str):
        ret = _get_string_value(controller, name)
        return val_type(ret)

    elif issubclass(val_type, int):
        ret = _get_int_value(controller, name)
        return val_type(ret)

    elif issubclass(val_type, bool):
        ret = _get_bool_value(controller, name)
        return val_type(ret)

    else:
        ret = _get_string_value(controller, name)
        try:
            return val_type(ret)
        except TypeError or ValueError:
            return infer_func(ret)


def _get_from_file(controller: bytes,
                   path: bytes,
                   name: bytes,
                   infer_func: Callable[[bytes], _FT],
                   val_type: Optional[Type[_FT]]) -> _FT:
    handle = c_void_p()
    buffer = create_string_buffer(_BUFFER_LEN)
    ret = cgroup_read_value_begin(controller, path, name, byref(handle), buffer, _BUFFER_LEN - 1)

    try:
        if ret == ErrorCode.EOF:
            return None
        elif ret is not 0:
            _raise_error(ret)

        result = list(buffer.value)

        while True:
            ret = cgroup_read_value_next(byref(handle), buffer, _BUFFER_LEN - 1)
            if ret == ErrorCode.EOF:
                break
            elif ret is not 0:
                _raise_error(ret)

            result += buffer.value

        result = bytes(result)
        try:
            if val_type is str:
                return result.rstrip().decode()
            else:
                return val_type(result)
        except TypeError or ValueError:
            return infer_func(result)

    finally:
        if handle.value is not None:
            ret = cgroup_read_value_end(byref(handle))
            if ret is not 0:
                _raise_error(ret)


def _set_of(controller: CGroupControllerPointer, name: bytes, value: Union[int, bool, str, bytes]) -> None:
    if isinstance(value, str):
        value = value.encode()

    if isinstance(value, bytes):
        ret = cgroup_set_value_string(controller, name, value)
    elif isinstance(value, int):
        if value > 0:
            ret = cgroup_set_value_uint64(controller, name, value)
        else:
            ret = cgroup_set_value_int64(controller, name, value)
    elif isinstance(value, bool):
        ret = cgroup_set_value_bool(controller, name, value)
    else:
        raise ValueError(f'Unsupported value type: {type(value)}')

    if ret is not 0:
        _raise_error(ret)


def _get_threads_of(controller: bytes, path: bytes) -> Iterable[int]:
    handler = c_void_p()
    pid = c_int()

    try:
        ret = cgroup_get_task_begin(path, controller, byref(handler), byref(pid))

        while ret is 0:
            yield pid.value
            ret = cgroup_get_task_next(byref(handler), byref(pid))

        if ret != ErrorCode.EOF:
            _raise_error(ret)
    finally:
        if handler.value is not None:
            ret = cgroup_get_task_end(byref(handler))
            if ret is not 0:
                _raise_error(ret)


def _get_processes_of(controller: bytes, path: bytes) -> Iterable[int]:
    pids = c_int_p()
    size = c_int()

    ret = cgroup_get_procs(path, controller, byref(pids), byref(size))
    if ret is not 0:
        _raise_error(ret)

    return (pids[i] for i in range(size.value))

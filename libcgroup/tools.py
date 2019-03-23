# coding: UTF-8

import errno
import os
from ctypes import byref, c_void_p
from typing import Iterable, NoReturn

from libcgroup_bind.error import ErrorCode, cgroup_get_last_errno, cgroup_strerror
from libcgroup_bind.iterators import (
    MountPoint, cgroup_get_controller_begin, cgroup_get_controller_end, cgroup_get_controller_next
)


def all_controller_names_bytes() -> Iterable[bytes]:
    handler = c_void_p()

    controller = MountPoint()
    ret = cgroup_get_controller_begin(byref(handler), byref(controller))

    while ret is 0:
        yield controller.name
        ret = cgroup_get_controller_next(byref(handler), byref(controller))

    if ret != ErrorCode.EOF:
        _raise_error(ret)

    cgroup_get_controller_end(byref(handler))


def all_controller_names() -> Iterable[str]:
    return map(str, all_controller_names_bytes())


def create_c_array(c_type, elements, length=None):
    elements_tup = tuple(elements)
    if length is None:
        length = len(elements_tup)
    return (c_type * length)(*elements_tup)


def _raise_error(ret: ErrorCode) -> NoReturn:
    err = cgroup_get_last_errno()
    if err is not 0:
        def_msg = '{}, {}.'.format(errno.errorcode[err], os.strerror(err))
        raise OSError(err, def_msg, cgroup_strerror(ret).decode())
    else:
        raise ValueError(cgroup_strerror(ret).decode())

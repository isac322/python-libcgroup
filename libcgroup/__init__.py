# coding: UTF-8

from libcgroup_bind.init import cgroup_init

# noinspection PyUnresolvedReferences
from .cgroup import CGroup
from .tools import _raise_error

ret = cgroup_init()
if ret is not 0:
    _raise_error(ret)
# coding: UTF-8

from __future__ import annotations

import os
from ctypes import byref, c_char_p, c_void_p, create_string_buffer
from itertools import chain
from typing import Callable, Dict, Iterable, Optional, Tuple, Type, TypeVar, Union

from libcgroup_bind.error import ErrorCode
from libcgroup_bind.groups import (
    CGroupControllerPointer, CGroupPointer, DeleteFlag, cgroup_add_controller, cgroup_compare_cgroup,
    cgroup_create_cgroup, cgroup_delete_cgroup_ext, cgroup_free, cgroup_get_cgroup, cgroup_get_controller,
    cgroup_get_value_name, cgroup_get_value_name_count, cgroup_new_cgroup, cgroup_set_permissions,
    cgroup_set_uid_gid
)
from libcgroup_bind.iterators import cgroup_read_value_begin, cgroup_read_value_end, cgroup_read_value_next
from libcgroup_bind.tasks import cgroup_attach_task, cgroup_attach_task_pid, cgroup_get_current_controller_path

from .tools import _raise_error, all_controller_names_bytes


def _infer_value(value: bytes) -> Union[int, str]:
    try:
        return int(value)
    except ValueError:
        return value.rstrip().decode()


_FT = TypeVar('_FT')
_BUFFER_LEN = 64


class CGroup:
    _cgroup: CGroupPointer
    _controllers: Dict[bytes, CGroupControllerPointer]

    _path: Union[os.PathLike, str]
    _auto_delete: bool
    _auto_delete_flag: DeleteFlag
    _deleted: bool = False

    def __init__(self, name_path: Union[os.PathLike, str], first_controller: str, *controllers: str,
                 dir_mode: int = None, file_mode: int = None, tasks_mode: int = None,
                 t_uid: int = None, t_gid: int = None, a_uid: int = None, a_gid: int = None,
                 ignore_ownership: bool = False,
                 auto_delete: bool = False, auto_delete_flag: DeleteFlag = DeleteFlag.NONE) -> None:
        """

        :param name_path: Control group which should be added (e.g. `cgrp_test/set1`)
        :type name_path: os.PathLike or str
        :param controller: The controller to which the control group to be added belongs (e.g. `cpuset` or `cpu`)
        :type controller: str
        :param dir_mode: Group directory permissions
        :type dir_mode: int
        :param file_mode: Group file permissions
        :type file_mode: int
        :param tasks_mode: Tasks file permissions
        :type tasks_mode: int
        :param t_uid: Owner of the tasks file
        :type t_uid: int
        :param t_gid: Owner group of the tasks file
        :type t_gid: int
        :param a_uid: Owner of the control group and all its files
        :type a_uid: int
        :param a_gid: Owner group of the control group and all its files
        :type a_gid: int
        :param ignore_ownership: When nozero, all errors are ignored
         when setting owner of the group and/or its tasks file.
        :type ignore_ownership: bool
        :param auto_delete: Delete this control group when this object is deleted
        :type auto_delete: bool
        """
        self._path = name_path

        self._auto_delete = auto_delete
        self._auto_delete_flag = auto_delete_flag

        self._cgroup = cgroup_new_cgroup(str(name_path).encode())
        if self._cgroup is None:
            _raise_error(ErrorCode.FAIL)

        self._controllers = dict()
        for controller_name in chain((first_controller,), controllers):
            cg_ctrl = cgroup_add_controller(self._cgroup, controller_name.encode())
            if cg_ctrl is None:
                _raise_error(ErrorCode.INVAL)

            self._controllers[controller_name.encode()] = cg_ctrl

        # set permission
        if dir_mode is not None or file_mode is not None:
            if dir_mode is None:
                dir_mode = 0o7777
            if file_mode is None:
                file_mode = 0o7777
            if tasks_mode is None:
                tasks_mode = 0o7777
            cgroup_set_permissions(self._cgroup, dir_mode, file_mode, tasks_mode)

        # set ownership
        if t_uid is None:
            t_uid = os.geteuid()
        if t_gid is None:
            t_gid = os.getegid()
        if a_uid is None:
            a_uid = os.geteuid()
        if a_gid is None:
            a_gid = os.getegid()
        ret = cgroup_set_uid_gid(self._cgroup, t_uid, t_gid, a_uid, a_gid)
        if ret is not 0:
            _raise_error(ret)

        # create cgroup
        ret = cgroup_create_cgroup(self._cgroup, ignore_ownership)
        if ret is not 0:
            _raise_error(ret)

        self.reload()

    def __del__(self) -> None:
        if not self._deleted and self._auto_delete:
            self.delete(self._auto_delete_flag)

    def __eq__(self, other: CGroup) -> bool:
        ret = cgroup_compare_cgroup(self._cgroup, other._cgroup)

        if ret is 0:
            return True
        elif ret == ErrorCode.NOTEQUAL:
            return False
        else:
            _raise_error(ret)

    @classmethod
    def from_existing(cls, name_path: Union[os.PathLike, str],
                      auto_delete: bool = False, auto_delete_flag: DeleteFlag = DeleteFlag.NONE) -> CGroup:
        obj = CGroup.__new__(cls)

        obj._path = name_path

        obj._auto_delete = auto_delete
        obj._auto_delete_flag = auto_delete_flag

        obj._cgroup = cgroup_new_cgroup(str(name_path).encode())
        if obj._cgroup is None:
            _raise_error(ErrorCode.FAIL)

        ret = cgroup_get_cgroup(obj._cgroup)
        if ret is not 0:
            _raise_error(ret)

        obj._controllers = dict()
        for controller in all_controller_names_bytes():
            cg_ctrl = cgroup_get_controller(obj._cgroup, controller)
            if cg_ctrl is not None:
                obj._controllers[controller] = cg_ctrl

        return obj

    @classmethod
    def from_pid(cls, pid: int, controller: str,
                 auto_delete: bool = False, auto_delete_flag: DeleteFlag = DeleteFlag.NONE) -> CGroup:
        name_path = c_char_p()
        ret = cgroup_get_current_controller_path(pid, controller.encode(), byref(name_path))
        if ret is not 0:
            _raise_error(ret)
        return cls.from_existing(str(name_path), auto_delete, auto_delete_flag)

    def delete(self, del_flag: DeleteFlag = DeleteFlag.NONE) -> None:
        if self._deleted:
            raise ValueError('This group has already been deleted.')

        self._deleted = True
        ret = cgroup_delete_cgroup_ext(self._cgroup, del_flag)
        if ret is not 0:
            _raise_error(ret)
        cgroup_free(byref(self._cgroup))

    def reload(self) -> None:
        cgroup_free(byref(self._cgroup))

        self._cgroup = cgroup_new_cgroup(str(self._path).encode())
        if self._cgroup is None:
            _raise_error(ErrorCode.FAIL)

        ret = cgroup_get_cgroup(self._cgroup)
        if ret is not 0:
            _raise_error(ret)

        for controller in self._controllers.keys():
            cg_ctrl = cgroup_get_controller(self._cgroup, controller)
            if cg_ctrl is not None:
                self._controllers[controller] = cg_ctrl
            else:
                _raise_error(ErrorCode.INVAL)

    # TODO: add sticky option
    def add_thread(self, pid: int) -> None:
        ret = cgroup_attach_task_pid(self._cgroup, pid)
        if ret is not 0:
            _raise_error(ret)

    # TODO: add sticky option
    def add_current_thread(self) -> None:
        ret = cgroup_attach_task(self._cgroup)
        if ret is not 0:
            _raise_error(ret)

    def get(self, name: str, infer_func: Callable[[bytes], _FT] = _infer_value) -> _FT:
        idx = name.index('.')
        if idx + 1 == len(name):
            raise ValueError('Can not infer controller and property name.')

        controller = name[:idx].encode()

        if controller not in self._controllers:
            raise ValueError(f'Invalid controller: {controller.decode()}')

        return self._get_from(controller, name.encode(), infer_func)

    def _get_from(self, controller: bytes, name: bytes, infer_func: Callable[[bytes], _FT]) -> _FT:
        handle = c_void_p()
        buffer = create_string_buffer(_BUFFER_LEN)
        ret = cgroup_read_value_begin(controller, self._path.encode(), name, byref(handle), buffer, _BUFFER_LEN - 1)

        try:
            if ret == ErrorCode.EOF.value:
                return None
            elif ret is not 0:
                _raise_error(ret)

            result = list(buffer.value)

            while True:
                ret = cgroup_read_value_next(byref(handle), buffer, _BUFFER_LEN - 1)
                if ret == ErrorCode.EOF.value:
                    break
                elif ret is not 0:
                    _raise_error(ret)

                result += buffer.value

            return infer_func(bytes(result))
        finally:
            if handle.value is not None:
                ret = cgroup_read_value_end(byref(handle))
                if ret is not 0:
                    _raise_error(ret)

    def get_from(self, controller: str, name: str, infer_func: Callable[[bytes], _FT] = _infer_value) -> _FT:
        return self._get_from(controller.encode(), name.encode(), infer_func)

    def get_all_from(self, controller: str,
                     infer_func: Callable[[bytes], _FT] = _infer_value) -> Iterable[Tuple[str, _FT]]:
        return self._get_all_from(controller.encode(), infer_func)

    def _get_all_from(self, controller: bytes, infer_func: Callable[[bytes], _FT]) -> Iterable[Tuple[str, _FT]]:
        cg_ctrl = self._controllers[controller]
        name_count = cgroup_get_value_name_count(cg_ctrl)

        for i in range(name_count):
            name = cgroup_get_value_name(cg_ctrl, i)
            yield name.decode(), self._get_from(controller, name, infer_func)

    def get_all(self, infer_func: Callable[[bytes], _FT] = _infer_value) -> Iterable[Tuple[str, _FT]]:
        for controller in self._controllers:
            yield from self._get_all_from(controller, infer_func)

# coding: UTF-8

from __future__ import annotations

import os
import shutil
from ctypes import byref, c_char_p
from itertools import chain
from pathlib import Path
from typing import Callable, ClassVar, Dict, Iterable, Optional, Tuple, Type, TypeVar, Union

from libcgroup_bind.error import ErrorCode
from libcgroup_bind.groups import (
    CGroupControllerPointer, CGroupPointer, DeleteFlag, cgroup_add_controller, cgroup_compare_cgroup,
    cgroup_create_cgroup, cgroup_delete_cgroup_ext, cgroup_free, cgroup_get_cgroup, cgroup_get_controller,
    cgroup_get_value_name, cgroup_get_value_name_count, cgroup_modify_cgroup, cgroup_new_cgroup,
    cgroup_set_permissions, cgroup_set_uid_gid
)
from libcgroup_bind.tasks import cgroup_attach_task, cgroup_attach_task_pid, cgroup_get_current_controller_path

from .mount_point import MountPoint
from .tools import (
    _all_controllers, _get_from_cached, _get_from_file, _get_processes_of, _get_threads_of, _raise_error, _set_of
)


def _infer_value(value: bytes) -> Union[int, str, None]:
    try:
        return int(value)
    except ValueError:
        result = value.rstrip()
        return result.decode() if result is not b'' else None


_FT = TypeVar('_FT')


class CGroup:
    root: ClassVar[CGroup]
    """ .. versionadded:: 0.2.0 """
    _cgroup: CGroupPointer
    _controllers: Dict[bytes, CGroupControllerPointer]

    _path: Union[os.PathLike, str]
    _raw_path: bytes
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
        self._raw_path = str(name_path).encode()

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
    def from_existing(cls,
                      name_path: Union[os.PathLike, str],
                      auto_delete: bool = False,
                      auto_delete_flag: DeleteFlag = DeleteFlag.NONE) -> CGroup:
        obj = CGroup.__new__(cls)

        obj._path = name_path
        obj._raw_path = str(name_path).encode()

        obj._auto_delete = auto_delete
        obj._auto_delete_flag = auto_delete_flag

        obj._cgroup = cgroup_new_cgroup(obj._raw_path)
        if obj._cgroup is None:
            _raise_error(ErrorCode.FAIL)

        ret = cgroup_get_cgroup(obj._cgroup)
        if ret is not 0:
            _raise_error(ret)

        obj._controllers = dict()
        for mount_point in _all_controllers():
            cg_ctrl = cgroup_get_controller(obj._cgroup, mount_point.name)
            if cg_ctrl is not None:
                obj._controllers[mount_point.name] = cg_ctrl

        return obj

    @classmethod
    def from_pid(cls,
                 pid: int,
                 controller: str,
                 auto_delete: bool = False,
                 auto_delete_flag: DeleteFlag = DeleteFlag.NONE) -> CGroup:
        name_path = c_char_p()
        ret = cgroup_get_current_controller_path(pid, controller.encode(), byref(name_path))
        if ret is not 0:
            _raise_error(ret)
        return cls.from_existing(str(name_path), auto_delete, auto_delete_flag)

    @classmethod
    def all_controller(cls) -> Iterable[MountPoint]:
        for mount_point in _all_controllers():
            yield MountPoint(mount_point.name.decode(), Path(mount_point.path.decode()))

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

        self._cgroup = cgroup_new_cgroup(self._raw_path)
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

    def get_threads_of(self, controller: str) -> Iterable[int]:
        return _get_threads_of(controller.encode(), self._raw_path)

    def get_threads(self) -> Iterable[int]:
        key_controller = next(iter(self._controllers.keys()))
        return _get_threads_of(key_controller, self._raw_path)

    # TODO: add sticky option
    def add_threads(self, *pids: int) -> None:
        for pid in pids:
            ret = cgroup_attach_task_pid(self._cgroup, pid)
            if ret is not 0:
                _raise_error(ret)

    # TODO: add sticky option
    def add_current_thread(self) -> None:
        ret = cgroup_attach_task(self._cgroup)
        if ret is not 0:
            _raise_error(ret)

    def remove_threads(self, *pids: int) -> None:
        self.root.add_threads(*pids)

    def get_processes_of(self, controller: str) -> Iterable[int]:
        return _get_processes_of(controller.encode(), self._raw_path)

    def get_processes(self) -> Iterable[int]:
        key_controller = next(iter(self._controllers.keys()))
        return _get_processes_of(key_controller, self._raw_path)

    def add_processes(self, *processes: int) -> None:
        for tgid in processes:
            for controller in self._controllers.values():
                _set_of(controller, b'cgroup.procs', tgid)
                self._modify()

    def add_current_process(self) -> None:
        """ .. versionadded:: 0.2.0 """
        self.add_processes(os.getpid())

    def remove_processes(self, *processes: int) -> None:
        """ .. versionadded:: 0.2.0 """
        self.root: CGroup

        for tgid in processes:
            for name in self._controllers.keys():
                controller = self.root._controllers[name]
                _set_of(controller, b'cgroup.procs', tgid)
                self.root._modify()

    def get(self,
            name: str,
            infer_func: Callable[[bytes], _FT] = _infer_value,
            val_type: Type[_FT] = None,
            use_cached: bool = True) -> _FT:
        idx = name.index('.')
        if idx + 1 == len(name):
            raise ValueError('Can not infer controller and property name.')

        controller = name[:idx].encode()

        if controller not in self._controllers:
            raise ValueError(f'Invalid controller: {controller.decode()}')

        return self._get_from(controller, name.encode(), infer_func, val_type, use_cached)

    def _get_from(self,
                  controller: bytes,
                  name: bytes,
                  infer_func: Callable[[bytes], _FT],
                  val_type: Optional[Type[_FT]],
                  use_cached: bool) -> _FT:
        if use_cached and name.startswith(controller):
            return _get_from_cached(self._controllers[controller], name, infer_func, val_type)
        else:
            return _get_from_file(controller, self._raw_path, name, infer_func, val_type)

    def get_from(self,
                 controller: str,
                 name: str,
                 infer_func: Callable[[bytes], _FT] = _infer_value,
                 val_type: Type[_FT] = None,
                 use_cached: bool = True) -> _FT:
        return self._get_from(controller.encode(), name.encode(), infer_func, val_type, use_cached)

    def get_all_from(self,
                     controller: str,
                     infer_func: Callable[[bytes], _FT] = _infer_value,
                     use_cached: bool = True) -> Iterable[Tuple[str, _FT]]:
        return self._get_all_from(controller.encode(), infer_func, use_cached)

    def _get_all_from(self,
                      controller: bytes,
                      infer_func: Callable[[bytes], _FT],
                      use_cached: bool) -> Iterable[Tuple[str, _FT]]:
        cg_ctrl = self._controllers[controller]
        name_count = cgroup_get_value_name_count(cg_ctrl)

        for i in range(name_count):
            name = cgroup_get_value_name(cg_ctrl, i)
            yield name.decode(), self._get_from(controller, name, infer_func, None, use_cached)

    def get_all(self,
                infer_func: Callable[[bytes], _FT] = _infer_value,
                use_cached: bool = True) -> Iterable[Tuple[str, _FT]]:
        for controller in self._controllers:
            yield from self._get_all_from(controller, infer_func, use_cached)

    def set_value_of(self, controller: str, name: str, value: Union[int, bool, str, bytes]) -> None:
        controller = controller.encode()

        if controller not in self._controllers:
            raise ValueError(f'Invalid controller: {controller}')

        _set_of(self._controllers[controller], name.encode(), value)
        self._modify()

    def set_value(self, name: str, value: Union[int, bool, str, bytes]) -> None:
        idx = name.index('.')
        if idx + 1 == len(name):
            raise ValueError('Can not infer controller and property name.')

        controller = name[:idx].encode()

        if controller not in self._controllers:
            raise ValueError(f'Invalid controller: {controller.decode()}')

        _set_of(self._controllers[controller], name.encode(), value)
        self._modify()

    def _modify(self) -> None:
        ret = cgroup_modify_cgroup(self._cgroup)
        if ret is not 0:
            _raise_error(ret)

    def move_to(self, new_name_path: Union[os.PathLike, str]) -> None:
        """
        Move the group pointed to by this object to another path.

        .. versionadded:: 0.2.0

        :param new_name_path: The path where the group will be moved
        :type new_name_path: os.PathLike or str
        """
        for controller in _all_controllers():
            from_dir = os.path.join(controller.path.decode(), self._path)
            to_dir = os.path.join(controller.path.decode(), new_name_path)

            if os.path.isdir(from_dir):
                if os.path.exists(to_dir):
                    raise FileExistsError(f'{to_dir} is already exist')
                shutil.move(from_dir, to_dir)

        self._path = new_name_path
        self._raw_path = str(new_name_path).encode()

        self.reload()

    @property
    def path(self) -> Path:
        """ .. versionadded:: 0.2.0 """
        return Path(self._path)

    @property
    def controllers(self) -> Tuple[str, ...]:
        """ .. versionadded:: 0.2.0 """
        return tuple(map(str, self._controllers.keys()))

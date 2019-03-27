# coding: UTF-8

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MountPoint:
    name: str
    path: Path

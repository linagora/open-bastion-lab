"""Provide a machine abstraction."""

from dataclasses import dataclass
from enum import StrEnum
from typing import overload, Protocol

from open_bastion_lab.config import Config
from open_bastion_lab.model import Role


class MachineState(StrEnum):
    UNKNOWN = "unknown"
    ABSENT = "absent"
    STARTED = "started"
    STOPPED = "stopped"


_type_number = dict([(r, num) for num, r in enumerate(Role)])

_PREFIX = "192.168.122"

# The libvirt default network gateway
_FIRST_HOST = 2

# Number of addresses owned by a single role
_HOSTS_PER_ROLE = 64


def mac_by_name(name: str, type: Role | None = None) -> str:
    """MAC address per machine.

    ⚠️ Uniqueness is not enforced, it holds iff names are strictly
    ``<prefix>-<count>`` and ``count`` is unique per role.

    """
    type_from_name, count = name.split("-")
    if type is None:
        type = Role(type_from_name)
    type_segment = f"{_type_number[type]:02x}"
    count_segment = f"{int(count):02x}"
    return ":".join(["52:54:00:12", type_segment, count_segment])


def ip_by_name(name: str, type: Role | None = None) -> str:
    """Host address per machine.

    Each role owns a block of ``_HOSTS_PER_ROLE`` addresses, the first ones
    being left to the host.

    """
    type_from_name, name_count = name.split("-")
    if type is None:
        type = Role(type_from_name)
    if not name_count.isdecimal():
        raise ValueError(f"Invalid machine name {name!r}")
    count = int(name_count)
    if not 0 < count < _HOSTS_PER_ROLE:
        raise ValueError(f"Invalid count in machine name {name!r}")
    offset = _type_number[type] * _HOSTS_PER_ROLE + (count - 1)
    return ".".join([_PREFIX, str(_FIRST_HOST + offset)])


@dataclass
class Machine:
    type: Role
    name: str
    state: MachineState = MachineState.UNKNOWN

    @property
    def ip(self) -> str:
        return ip_by_name(self.name, self.type)

    @property
    def mac(self) -> str:
        return mac_by_name(self.name, self.type)


class HypervisorProxy(Protocol):

    async def close(self) -> None: ...

    @overload
    async def check(self) -> list[Machine]: ...

    @overload
    async def check(self, machine: Machine) -> Machine: ...

    async def create(self, machine: Machine) -> bool: ...

    async def start(self, machine: Machine) -> bool: ...

    async def stop(self, machine: Machine) -> bool: ...

    async def delete(self, machine: Machine) -> bool: ...

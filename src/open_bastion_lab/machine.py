"""Provide a machine abstraction."""

from enum import StrEnum
from typing import overload, Protocol

from open_bastion_lab.model import Role


class MachineState(StrEnum):
    UNKNOWN = "unknown"
    ABSENT = "absent"
    STARTED = "started"
    STOPPED = "stopped"


class Machine(Protocol):
    """What a command of the lab asks of a machine.

    The addresses are the ones the machine has on the network of its
    hypervisor, which is the only side that knows how to derive them.

    """

    type: Role
    name: str
    state: MachineState

    @property
    def ip(self) -> str: ...

    @property
    def mac(self) -> str: ...


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

    async def snapshot(self, machine: Machine, name: str) -> bool: ...

    async def restore(self, machine: Machine, name: str) -> bool: ...

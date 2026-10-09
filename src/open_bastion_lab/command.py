from typing import Protocol

from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy


class Command(Protocol):

    async def close(self) -> None: ...

    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int: ...

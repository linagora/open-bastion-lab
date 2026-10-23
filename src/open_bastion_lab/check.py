"""The check command."""

from typing import override

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy


class CheckCommand(Command):

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        print("Machines:")
        for machine in machines:
            ip_trailer = machine.ip if machine.ip is not None else "Unknown IP"
            print(f"- {machine.name} {machine.state} ({ip_trailer})")

        return 0

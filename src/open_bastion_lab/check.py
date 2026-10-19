"""The check command."""

from typing import override

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, MachineState


class CheckCommand(Command):

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        print("Machines:")
        for machine in machines:
            state: str
            if machine.state == MachineState.STARTED:
                state = "🟩"
            elif machine.state == MachineState.STOPPED:
                state = "🟠"
            elif machine.state == MachineState.ABSENT:
                state = "🔴"
            elif machine.state == MachineState.UNKNOWN:
                state = "❓"
            ip_trailer = machine.ip if machine.ip is not None else "Unknown IP"
            print(f"- {state} {machine.name} {machine.state} ({ip_trailer})")

        return 0

"""The stop command."""

from typing import override, Any, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, Machine, MachineState

LOGGER = logging.getLogger(__name__)


class StopCommand(Command):

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        tasks: list[Coroutine[Any, Any, bool]] = []
        for machine in machines:
            if machine.state is MachineState.STARTED:
                tasks.append(hypervisor.stop(machine))
            elif machine.state is MachineState.STOPPED:
                LOGGER.debug(f"Machine {machine.name} already stopped")
            elif machine.state is MachineState.ABSENT:
                LOGGER.debug(f"Skipping missing {machine.name}")
            elif machine.state is MachineState.UNKNOWN:
                LOGGER.debug(f"Skipping {machine.name} in unknown state")

        results = await asyncio.gather(*tasks)
        machines = await hypervisor.check()

        return (
            0
            if all([machine.state == MachineState.STOPPED for machine in machines])
            else 1
        )

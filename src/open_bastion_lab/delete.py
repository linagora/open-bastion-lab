"""The delete command."""

from typing import override, Any, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, MachineState

LOGGER = logging.getLogger(__name__)


class DeleteCommand(Command):

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        tasks: list[Coroutine[Any, Any, bool]] = []
        for machine in machines:
            if machine.state is MachineState.ABSENT:
                LOGGER.debug(f"Machine {machine.name} doesn't exists")
            elif machine.state is MachineState.UNKNOWN:
                LOGGER.debug(f"Skipping {machine.name} in unknown state")
            else:
                tasks.append(hypervisor.delete(machine))

        results = await asyncio.gather(*tasks)
        machines = await hypervisor.check()

        return (
            0
            if all([machine.state == MachineState.ABSENT for machine in machines])
            else 1
        )

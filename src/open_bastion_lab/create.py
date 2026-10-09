"""The create command."""

from typing import override, Any, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, MachineState

LOGGER = logging.getLogger(__name__)


class CreateCommand(Command):

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        tasks: list[Coroutine[Any, Any, bool]] = []
        for machine in machines:
            if (
                machine.state is MachineState.STARTED
                or machine.state is MachineState.STOPPED
            ):
                LOGGER.debug(f"Machine {machine.name} already exists")
            elif machine.state is MachineState.UNKNOWN:
                LOGGER.debug(f"Skipping {machine.name} in unknown state")
            elif machine.state is MachineState.ABSENT:
                tasks.append(hypervisor.create(machine))

        results = await asyncio.gather(*tasks)
        machines = await hypervisor.check()

        return (
            0
            if all(
                [
                    machine.state
                    in (
                        MachineState.STARTED,
                        MachineState.STOPPED,
                    )
                    for machine in machines
                ]
            )
            else 1
        )

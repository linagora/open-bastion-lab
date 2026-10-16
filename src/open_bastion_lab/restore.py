"""The restore command."""

from typing import override, Any, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, Machine, MachineState
from open_bastion_lab.start import is_port_open

LOGGER = logging.getLogger(__name__)

SSH_TRIES = 60


async def wait_for_ssh(machine: Machine) -> bool:
    tries = 0
    LOGGER.debug("Waiting for domain %s SSH…", machine.name)
    while tries < SSH_TRIES:
        if await is_port_open(machine.ip, 22):
            return True
        await asyncio.sleep(1)
        tries += 1
    LOGGER.error(
        "Domain %s did not answer on %s after %s tries", machine.name, machine.ip, tries
    )
    return False


class RestoreCommand(Command):
    name: str

    def __init__(self, name: str):
        self.name = name

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()

        async def restore_and_wait(machine: Machine) -> bool:
            return await hypervisor.restore(machine, self.name) and await wait_for_ssh(
                machine
            )

        tasks: list[Coroutine[Any, Any, bool]] = [
            restore_and_wait(machine)
            for machine in machines
            if machine.state in (MachineState.STARTED, MachineState.STOPPED)
        ]
        results = await asyncio.gather(*tasks)

        return 0 if all(results) else 1

"""The snapshot command."""

from typing import override, Any, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.machine import HypervisorProxy, Machine, MachineState
from open_bastion_lab.restore import wait_for_ssh

LOGGER = logging.getLogger(__name__)


class SnapshotCommand(Command):
    name: str

    def __init__(self, name: str):
        self.name = name

    @override
    async def close(self) -> None:
        pass

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()

        async def snapshot_and_wait(machine: Machine) -> bool:
            if not await hypervisor.snapshot(machine, self.name):
                return False
            if machine.state is not MachineState.STARTED:
                return True
            return await wait_for_ssh(machine)

        tasks: list[Coroutine[Any, Any, bool]] = [
            snapshot_and_wait(machine)
            for machine in machines
            if machine.state in (MachineState.STARTED, MachineState.STOPPED)
        ]
        results = await asyncio.gather(*tasks)

        return 0 if all(results) else 1

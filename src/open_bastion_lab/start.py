"""The start command."""

from typing import override, Any, Callable, Coroutine
import asyncio
import logging

from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.imds import InstanceMetadataServer
from open_bastion_lab.machine import HypervisorProxy, Machine, MachineState

LOGGER = logging.getLogger(__name__)


async def is_port_open(host: str, port: int = 22, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    await writer.wait_closed()
    return True


class StartCommand(Command):
    _imds_service: InstanceMetadataServer | None

    def __init__(self):
        self._imds_service = None

    @override
    async def close(self) -> None:
        if self._imds_service is not None:
            await self._imds_service.stop()

    @override
    async def __call__(self, *, config: Config, hypervisor: HypervisorProxy) -> int:
        machines = await hypervisor.check()
        tasks: list[Coroutine[Any, Any, bool]] = []

        self._imds_service = InstanceMetadataServer(config)
        await self._imds_service.start()

        async def start_and_wait(machine: Machine):
            assert(self._imds_service)
            if machine.state is MachineState.ABSENT:
                await hypervisor.create(machine)
            await hypervisor.start(machine)

            tries = 0
            LOGGER.debug("Waiting for domain %s SSH…", machine.name)
            while tries < 30:
                sshp = await is_port_open(machine.ip, 22)
                if sshp is True and self._imds_service.seeded(machine.name):
                    break
                await asyncio.sleep(1)
                tries += 1

            await asyncio.sleep(3)
            # Hack to let cloud-init finish the guest setup

        for machine in machines:
            if machine.state is MachineState.ABSENT:
                tasks.append(start_and_wait(machine))
            elif machine.state is MachineState.UNKNOWN:
                LOGGER.debug(f"Skipping {machine.name} in unknown state")
            elif machine.state is MachineState.STOPPED:
                tasks.append(start_and_wait(machine))
            elif machine.state is MachineState.STARTED:
                LOGGER.debug(f"Machine {machine.name} already started")

        results = await asyncio.gather(*tasks)
        machines = await hypervisor.check()

        return (
            0
            if all([machine.state == MachineState.STARTED for machine in machines])
            else 1
        )

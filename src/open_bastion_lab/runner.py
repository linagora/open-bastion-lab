"""Run ob-lab commands against a fleet."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from open_bastion_lab.check import CheckCommand
from open_bastion_lab.command import Command
from open_bastion_lab.config import Config
from open_bastion_lab.create import CreateCommand
from open_bastion_lab.delete import DeleteCommand
from open_bastion_lab.machine import HypervisorProxy
from open_bastion_lab.restore import RestoreCommand
from open_bastion_lab.snapshot import SnapshotCommand
from open_bastion_lab.start import StartCommand
from open_bastion_lab.stop import StopCommand
from open_bastion_lab.virt import LibvirtProxy

DEFAULT_SNAPSHOT = "lab"

COMMANDS = ["check", "create", "delete", "restore", "snapshot", "start", "stop"]


@asynccontextmanager
async def hypervisor_proxy(config: Config) -> AsyncIterator[HypervisorProxy]:
    proxy: HypervisorProxy | None = None
    if config.hypervisor == "libvirt":
        proxy = LibvirtProxy(config)
    if proxy is None:
        raise RuntimeError(f"Unsupported hypervisor {config.hypervisor}")

    try:
        yield proxy
    finally:
        await proxy.close()


@asynccontextmanager
async def command_wrapper(
    name: str, snapshot: str = DEFAULT_SNAPSHOT
) -> AsyncIterator[Command]:
    command: Command
    if name == "check":
        command = CheckCommand()
    elif name == "create":
        command = CreateCommand()
    elif name == "delete":
        command = DeleteCommand()
    elif name == "restore":
        command = RestoreCommand(snapshot)
    elif name == "snapshot":
        command = SnapshotCommand(snapshot)
    elif name == "start":
        command = StartCommand()
    elif name == "stop":
        command = StopCommand()
    else:
        raise RuntimeError(f"Not yet implemented, {name}")
    try:
        yield command
    finally:
        await command.close()


async def run(name: str, config: Config, snapshot: str = DEFAULT_SNAPSHOT) -> int:
    """Run the command of the given name and return its status."""
    async with hypervisor_proxy(config) as hypervisor:
        async with command_wrapper(name, snapshot) as command:
            return await command(config=config, hypervisor=hypervisor)

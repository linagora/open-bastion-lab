from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator
import asyncio
import argparse
import logging
import sys


from open_bastion_lab.check import CheckCommand
from open_bastion_lab.config import Config
from open_bastion_lab.command import Command
from open_bastion_lab.config import load_config
from open_bastion_lab.create import CreateCommand
from open_bastion_lab.delete import DeleteCommand
from open_bastion_lab.machine import HypervisorProxy
from open_bastion_lab.start import StartCommand
from open_bastion_lab.stop import StopCommand
from open_bastion_lab.virt import LibvirtProxy

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ob-lab")
    parser.add_argument(
        "-f",
        "--fleet",
        type=str,
        default="",
        help="fleet to deploy",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="enable debug output",
    )
    parser.add_argument(
        "command",
        choices=["check", "create", "delete", "start", "stop"],
        help="command to run",
    )
    return parser


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
async def command_wrapper(name: str) -> AsyncIterator[Command]:
    command: Command
    if name == "check":
        command = CheckCommand()
    elif name == "create":
        command = CreateCommand()
    elif name == "delete":
        command = DeleteCommand()
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.debug == True:
        logging.basicConfig(level=logging.DEBUG)

    config = load_config(fleet=args.fleet)

    status = 0

    async def _main():
        nonlocal status
        async with hypervisor_proxy(config) as hypervisor:
            async with command_wrapper(args.command) as command:
                status = await command(config=config, hypervisor=hypervisor)

    asyncio.run(_main())

    return status

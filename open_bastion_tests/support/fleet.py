"""The fleet under test, driven with the ob-lab package."""

from pathlib import Path

import asyncio
import logging
import subprocess
import time

from open_bastion_lab.config import Config, load_config
from open_bastion_lab.machine import Machine, MachineState
from open_bastion_lab.runner import DEFAULT_SNAPSHOT, hypervisor_proxy, run

from open_bastion_tests.support import command, guest_agent, public_key
from open_bastion_tests.support.guest_agent import AgentResult

LOGGER = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"

# Statuses cloud-init reports once it is done, errors included: a recoverable
# error did not keep the guest from finishing its first boot.
CLOUD_INIT_DONE = (0, 2)
CLOUD_INIT_TIMEOUT = 900.0
CLOUD_INIT_ATTEMPT = 120.0
CLOUD_INIT_DELAY = 5.0

# Where the machines keep the authorizations the portal gave them
AUTHORIZATION_CACHE = "/var/cache/open-bastion/auth"

# The password cloud-init gives the accounts of the machines
DEFAULT_PASSWORD = "password"

# Options of the ssh commands that may have to answer a password prompt.
# BatchMode is left out on purpose: it makes ssh refuse to ask for a password.
PASSWORD_SSH_OPTIONS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "PreferredAuthentications=password",
    "-o",
    "PubkeyAuthentication=no",
    "-o",
    "NumberOfPasswordPrompts=1",
]

# Options of the ssh commands the tests run against the maintainer account.
# The host configuration and the agent of whoever runs the tests are left
# out: the machines only accept the key of the tests, and the server
# disconnects once too many identities have been refused.
SSH_OPTIONS = [
    "-F",
    "/dev/null",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
]


def data(*parts: str) -> Path:
    """Path to one of the test owned copies of the example files."""
    return DATA_DIR.joinpath(*parts)


class Fleet:
    """The machines a scenario runs against.

    The machines are created once, snapshotted, and every feature gets that
    snapshot back, so what a feature does to the guests never leaks into the
    next one.

    """

    name: str
    config: Config
    key: Path

    def __init__(self, name: str, key: Path):
        self.name = name
        self.config = load_config(fleet=name)
        self.key = key
        # The guests are given the key of the tests on top of the ones the
        # configuration of the lab declares, if any.
        self.config.authorized_keys = [
            public_key(key).read_text().strip(),
            *self.config.authorized_keys,
        ]

    def existing(self) -> list[Machine]:
        """Machines of the fleet that already exist on the hypervisor."""
        return [
            machine
            for machine in self.machines()
            if machine.state is not MachineState.ABSENT
        ]

    def machines(self) -> list[Machine]:
        return asyncio.run(self._machines())

    def machine(self, name: str) -> Machine:
        machines = self.machines()
        for machine in machines:
            if machine.name == name:
                return machine
        known = ", ".join(machine.name for machine in machines)
        raise LookupError(f"No machine {name} in fleet {self.name} ({known})")

    async def _machines(self) -> list[Machine]:
        async with hypervisor_proxy(self.config) as hypervisor:
            return await hypervisor.check()

    def start(self) -> None:
        self._run("start")

    def wait_for_cloud_init(self) -> None:
        """Wait for the guests to be done with their first boot.

        They install packages then, and one of them is openssh-server, so
        the machines may still be closed when the fleet reports them as
        started. A snapshot taken before that settles restores a guest in
        the middle of a package installation.

        """
        deadline = time.monotonic() + CLOUD_INIT_TIMEOUT
        for machine in self.machines():
            LOGGER.info("Waiting for cloud-init on %s", machine.name)
            result = self._cloud_init_status(machine, deadline)
            if result.returncode not in CLOUD_INIT_DONE:
                raise RuntimeError(
                    f"cloud-init did not finish on {machine.name}:\n"
                    f"{result.stdout}\n{result.stderr}"
                )

    def _cloud_init_status(
        self, machine: Machine, deadline: float
    ) -> subprocess.CompletedProcess[str]:
        """Ask a guest whether cloud-init is done, until the deadline."""
        args = self._cloud_init_args(machine)
        result = command.run(args, timeout=CLOUD_INIT_ATTEMPT)
        while result.returncode not in CLOUD_INIT_DONE and time.monotonic() < deadline:
            LOGGER.debug(
                "cloud-init on %s is not done yet: %s",
                machine.name,
                result.stderr.strip(),
            )
            time.sleep(CLOUD_INIT_DELAY)
            result = command.run(args, timeout=CLOUD_INIT_ATTEMPT)
        return result

    def _cloud_init_args(self, machine: Machine) -> list[str]:
        return [
            command.which("ssh"),
            "-i",
            str(self.key),
            *SSH_OPTIONS,
            f"maintainer@{machine.ip}",
            "cloud-init status --wait",
        ]

    def copy_public_key(self, machine: Machine, account: str, key: Path) -> None:
        """Leave the public key of an account on a machine, as its owner would.

        The account logs in with the trivial password the fleet gives it,
        the way it can before the machine is configured, and copies its key
        with ssh-copy-id.

        """
        askpass = self.key.parent / "askpass.sh"
        askpass.write_text(f'#!/bin/sh\nprintf "%s\\n" "{DEFAULT_PASSWORD}"\n')
        askpass.chmod(0o700)

        args = [
            command.which("setsid"),
            "-w",
            command.which("ssh-copy-id"),
            "-i",
            str(public_key(key)),
            *PASSWORD_SSH_OPTIONS,
            f"{account}@{machine.ip}",
        ]
        result = command.run(
            args,
            env=command.environment(
                SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY=":0"
            ),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to copy the key of {account} to {machine.name}: {result.stderr}"
            )

    def forget_authorizations(self) -> None:
        """Drop the answers the machines cached.

        They keep the authorizations the portal gave them for a minute, so
        a change of the rules of the portal is only immediate once the
        cache is gone. What is dropped is a cache: the enrolment of the
        machines lives elsewhere.

        """
        for machine in self.machines():
            result = command.run(
                [
                    *self._ssh_args(machine),
                    f"sudo rm -rf {AUTHORIZATION_CACHE}",
                ]
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to clear the cache of {machine.name}: {result.stderr}"
                )

    def _ssh_args(self, machine: Machine) -> list[str]:
        """Arguments of a command run on a machine as the maintainer."""
        return [
            command.which("ssh"),
            "-i",
            str(self.key),
            *SSH_OPTIONS,
            f"maintainer@{machine.ip}",
        ]

    def run_as_root(self, machine: Machine, script: str) -> AgentResult:
        """Run a shell command as root in a guest, through its agent.

        A configured fleet takes sudo away from every local account, so a
        check that reads a root-owned file has no SSH path left: see
        :mod:`open_bastion_tests.support.guest_agent`.

        """
        return guest_agent.shell(machine.name, script)

    def read_as_root(self, machine: Machine, path: str) -> str:
        """What a root-owned file of a guest holds."""
        return guest_agent.read_text(machine.name, path)

    def delete(self) -> None:
        self._run("delete")

    def snapshot(self, name: str = DEFAULT_SNAPSHOT) -> None:
        self._run("snapshot", name)

    def restore(self, name: str = DEFAULT_SNAPSHOT) -> None:
        self._run("restore", name)

    def _run(self, command: str, snapshot: str = DEFAULT_SNAPSHOT) -> None:
        status = asyncio.run(run(command, self.config, snapshot))
        if status != 0:
            raise RuntimeError(f"ob-lab {command} failed on fleet {self.name}")

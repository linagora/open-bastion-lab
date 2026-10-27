"""The self-extracting installers ob-builder writes with ``--output-shell``.

They are the deployment for an administrator without an Ansible control node:
ob-builder writes one script per role, the administrator copies each to its
target and runs it as root. The host enrols itself with the device
authorization grant, so it publishes a code and waits for the portal to
approve it; the administrator who approves is the one this module holds a
session for.

Each step of that procedure is a method here, and the Background of the
feature calls them in order — starting an installer and approving its
enrolment cannot be the same call. Every method does its work once and then
answers from what it recorded: the Background runs again before each of the
scenarios, and what it describes is one deployment, not sixteen.

The lab serves an unsigned package repository, while an installer's sources
entry names the signature it expects. The package is therefore installed
from that repository first, and the installer runs with ``--skip-install
--force`` — the post-install script has created ``/etc/open-bastion``
already — as the project's own ``local-test/deploy-shell.sh`` does.
Everything from the configuration on is the installer's own work.

"""

from dataclasses import dataclass, field
from pathlib import Path

import json
import logging
import re
import shlex
import time

from open_bastion_lab.machine import Machine
from open_bastion_lab.model import Role

from open_bastion_tests.support import guest_agent
from open_bastion_tests.support.fleet import Fleet
from open_bastion_tests.support.llng import Llng, Session
from open_bastion_tests.support.deployment import Administrator, apt_repository_url

LOGGER = logging.getLogger(__name__)

INSTALLER = "/tmp/open-bastion-installer.sh"
INSTALLER_LOG = "/tmp/open-bastion-installer.log"
INSTALLER_STATUS = "/tmp/open-bastion-installer.status"
ENROLL_STATE = "/run/open-bastion/enroll-state.json"
SOURCES = "/etc/apt/sources.list.d/open-bastion.list"
BASTION_ID = "/usr/bin/ob-bastion-id"

# What an installer artefact bakes, as the script spells it
ALLOWED_PATTERN = re.compile(r'^ALLOWED_BASTIONS="(?P<ids>[^"]*)"$', re.MULTILINE)

# The relying party the demo portal enrols hosts with, and its secret.
CLIENT_SECRET = "pamsecret"

# How long a host is given to publish the code it waits on
STATE_TIMEOUT = 180.0
STATE_POLL = 0.5

# Installing the package is a transaction with the repository, the
# deployment itself enrols and configures a host.
PACKAGE_TIMEOUT = 600.0
INSTALL_TIMEOUT = 1800.0


class InstallerError(RuntimeError):
    """The installers did not deploy the fleet."""


@dataclass
class Installation:
    """What running the installer of a role on one machine did."""

    machine: str
    role: Role
    returncode: int
    log: Path

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    def describe(self) -> str:
        return (
            f"the {self.role} installer of {self.machine} returned "
            f"{self.returncode}, see {self.log}"
        )


@dataclass
class InstallerBasedDeployment:
    """open-bastion installed on a fleet by its self-extracting installers."""

    fleet: Fleet
    administrator: Administrator
    llng: Llng
    session: Session
    work_dir: Path
    # The artefact of each role, and the installer running on each host
    artefacts: dict[Role, Path] = field(default_factory=dict)
    running: dict[str, int] = field(default_factory=dict)
    # The device code each host published, and what its installer did
    approvals: dict[str, str] = field(default_factory=dict)
    installations: dict[str, Installation] = field(default_factory=dict)
    # The fleet's bastion, and the id its backends allow
    bastion: str = ""
    identifier: str = ""

    def build_bastion_installer(self) -> Path:
        """The bastion's artefact: one role, and no allowlist to embed."""
        return self._build(Role.BASTION)

    def build_backend_installer(self, bastion: str) -> Path:
        """The backends' artefact, allowing the id the bastion printed.

        The id only exists once the bastion is enrolled, which is why the
        backends are built after the bastion has run.

        """
        machine = self.fleet.machine(bastion)
        if machine.type is not Role.BASTION:
            raise InstallerError(f"{bastion} is no bastion of the fleet")
        self.bastion = bastion
        if not self.identifier:
            self.identifier = self.bastion_id(machine)
        return self._build(Role.BACKEND, allowed_bastions=self.identifier)

    def _build(self, role: Role, *, allowed_bastions: str | None = None) -> Path:
        installer = self.artefacts.get(role)
        if installer is None or not installer.is_file():
            installer = self.administrator.generate_installer(
                role, allowed_bastions=allowed_bastions
            )
            self.artefacts[role] = installer
        return installer

    def start(self, host: str) -> None:
        """Copy the installer of the host's role there and start it, as root.

        It is started rather than waited on: it enrols the host and stops
        until the portal approves, and the approval is the next step.

        """
        if host in self.installations or host in self.running:
            return
        machine = self.fleet.machine(host)
        installer = self.artefacts.get(machine.type)
        if installer is None:
            raise InstallerError(
                f"The {machine.type} installer has not been generated, so it "
                f"cannot run on {host}"
            )
        self.install_package(machine)
        guest_agent.write_text(
            machine.name, INSTALLER, installer.read_text(), mode=0o755
        )
        guest_agent.shell(machine.name, f"rm -f -- {ENROLL_STATE}")
        self.running[host] = guest_agent.start(
            machine.name, self._argv(machine), env=self._environment()
        )
        LOGGER.info("The %s installer started on %s", machine.type, host)

    def approve(self, host: str) -> str:
        """Approve the code the host published, and answer it.

        An installer that fails before it enrols writes its status and never
        publishes a code: waiting for the whole timeout would report a
        missing approval for what is a failed installation, so the status
        file is watched as well.

        """
        if host in self.approvals:
            return self.approvals[host]
        deadline = time.monotonic() + STATE_TIMEOUT
        while time.monotonic() < deadline:
            try:
                state = json.loads(guest_agent.read_text(host, ENROLL_STATE))
            except (guest_agent.AgentError, json.JSONDecodeError):
                if guest_agent.exists(host, INSTALLER_STATUS):
                    raise InstallerError(
                        f"The installer of {host} stopped before it published "
                        f"a device code:\n{self._tail(host)}"
                    )
                time.sleep(STATE_POLL)
                continue
            self.llng.approve_device(self.session, state["user_code"])
            self.approvals[host] = state["user_code"]
            return state["user_code"]
        raise InstallerError(
            f"{host} published no device code in {STATE_TIMEOUT:.0f}s, "
            f"see {INSTALLER_LOG} on the machine"
        )

    def finish(self, host: str) -> Installation:
        """Wait for the installer of a host, and keep what it did."""
        installation = self.installations.get(host)
        if installation is not None:
            return installation
        pid = self.running.get(host)
        if pid is None:
            raise InstallerError(f"The installer of {host} was never started")
        machine = self.fleet.machine(host)
        guest_agent.wait(
            machine.name, pid, self._argv(machine), timeout=INSTALL_TIMEOUT
        )

        log = self.work_dir / f"installer-{host}.log"
        log.write_text(guest_agent.read_text(machine.name, INSTALLER_LOG))
        status = guest_agent.read_text(machine.name, INSTALLER_STATUS).strip()
        installation = Installation(
            machine=host,
            role=machine.type,
            returncode=int(status) if status.lstrip("-").isdigit() else -1,
            log=log,
        )
        self.installations[host] = installation
        return installation

    def _argv(self, machine: Machine) -> list[str]:
        """What runs the installer of a machine, with its output kept.

        The inventory of the playbook deployment names the server group of
        each host, and the configuration embeds none: the installer is given
        the group of its role, as the play would.

        """
        return [
            "/bin/bash",
            "-c",
            f"{INSTALLER} --yes --skip-install --force"
            f" --server-group {machine.type}"
            f" >{INSTALLER_LOG} 2>&1; echo $? >{INSTALLER_STATUS}",
        ]

    def _environment(self) -> dict[str, str]:
        """What ob-enroll needs to publish its code, and to authenticate."""
        return {
            "OB_ENROLL_STATE_FILE": ENROLL_STATE,
            "OB_CLIENT_SECRET": CLIENT_SECRET,
        }

    def _tail(self, host: str) -> str:
        """What the installer of a host printed last, for a failure message."""
        try:
            return guest_agent.read_text(host, INSTALLER_LOG)[-2000:]
        except guest_agent.AgentError:
            return f"no {INSTALLER_LOG} on the machine"

    def install_package(self, machine: Machine) -> None:
        """Install open-bastion the way the inventory gives it to the fleet."""
        entry = f"deb [trusted=yes] {apt_repository_url()} ./\n"
        script = "\n".join(
            [
                "set -e",
                f"printf '%s' {shlex.quote(entry)} >{SOURCES}",
                "apt-get update -q",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -q open-bastion",
            ]
        )
        result = guest_agent.shell(machine.name, script, timeout=PACKAGE_TIMEOUT)
        if not result.succeeded:
            raise InstallerError(
                f"Cannot install open-bastion on {machine.name}: {result.describe()}"
            )

    def bastion_id(self, machine: Machine) -> str:
        """The id the bastion printed, which its backends allow."""
        result = guest_agent.shell(machine.name, BASTION_ID)
        identifier = result.stdout.strip().splitlines()
        if not result.succeeded or not identifier:
            raise InstallerError(
                f"{BASTION_ID} answered nothing on {machine.name}: {result.describe()}"
            )
        LOGGER.info("The id of %s is %s", machine.name, identifier[-1].strip())
        return identifier[-1].strip()

    def allowed_bastions(self, role: Role) -> str:
        """The ids an installer artefact allows, as it bakes them."""
        installer = self.artefacts.get(role)
        if installer is None:
            raise InstallerError(f"No installer of the {role} role was built")
        found = ALLOWED_PATTERN.search(installer.read_text())
        if found is None:
            raise InstallerError(f"{installer} carries no allowed bastions")
        return found.group("ids")

"""Steps of the deployment, and what it left behind.

The self-extracting installers are run step by step, as the documentation of
the shell deployment has it: each step does one thing and keeps what it did,
so the Background of the feature can run again before every scenario.

The checks read the machines as root: a fleet in maximum security has no
local account left that can elevate, so they ask the QEMU guest agent, which
runs before PAM and sshd. See :mod:`open_bastion_tests.support.guest_agent`.

"""

from pytest_bdd import given, parsers, then

import logging
import re

import pytest

from open_bastion_lab.model import Role

from open_bastion_tests.support import guest_agent
from open_bastion_tests.support.deployment import Administrator
from open_bastion_tests.support.fleet import Fleet
from open_bastion_tests.support.installer import InstallerBasedDeployment
from open_bastion_tests.support.llng import Llng, Session

LOGGER = logging.getLogger(__name__)

# What the setup scripts write, and what the scenarios read back
CONFIG = "/etc/open-bastion/openbastion.conf"
SUDO_STACK = "/etc/pam.d/sudo"
ALLOWED_BASTIONS = "/etc/open-bastion/allowed_bastions"
BASTION_ID = "/usr/bin/ob-bastion-id"

# The sudo stack of a maximum security host asks the portal, and refuses
# what it does not answer
SUDO_STACK_PATTERNS = (r"pam_openbastion\.so", r"pam_deny\.so")


@given(
    parsers.re(
        r"the administrator generates the installer of the bastion with "
        r'the "(?P<name>[^"]+)" configuration'
    )
)
def administrator_generates_the_bastion_installer(
    name: str, administrator: Administrator, deployment: InstallerBasedDeployment
) -> None:
    """ob-builder writes the bastion's artefact, once for the feature."""
    installer = deployment.build_bastion_installer(administrator, name)
    LOGGER.info("The bastion installer of %s is %s", name, installer)


@given(
    parsers.re(
        r"the administrator generates the installer of the backends allowing "
        r'the bastion "(?P<host>[^"]+)"'
    )
)
def administrator_generates_the_backend_installer(
    host: str,
    administrator: Administrator,
    fleet: Fleet,
    deployment: InstallerBasedDeployment,
) -> None:
    """The backends allow the id the bastion printed, and only that id.

    It is baked into the installer, which is why the backends are built
    after the bastion is enrolled.

    """
    installer = deployment.build_backend_installer(administrator, fleet, host)
    allowed = deployment.allowed_bastions(Role.BACKEND)
    if allowed != deployment.identifier:
        pytest.fail(
            f"The backend installer allows {allowed!r} instead of the id "
            f"{deployment.identifier} of {host}",
            pytrace=False,
        )
    LOGGER.info("The backends allow %s, the id of %s, in %s", allowed, host, installer)


@given(parsers.re(r'the administrator runs the installer on "(?P<host>[^"]+)"'))
def administrator_runs_the_installer(
    host: str, fleet: Fleet, deployment: InstallerBasedDeployment
) -> None:
    """The installer is copied to the host and started, as root.

    It enrols the host and then waits, so it is not waited on here: the code
    it publishes is approved by the next step.

    """
    deployment.start(fleet, host)


@given(parsers.re(r'the administrator approves the enrolment of "(?P<host>[^"]+)"'))
def administrator_approves_the_enrolment(
    host: str,
    llng: Llng,
    portal_session: Session,
    deployment: InstallerBasedDeployment,
) -> None:
    """The device code the host published is approved on the portal."""
    code = deployment.approve(llng, portal_session, host)
    LOGGER.info("The device code %s of %s was approved", code, host)


@given(parsers.re(r'the installer of "(?P<host>[^"]+)" succeeded'))
def installer_succeeded(
    host: str, fleet: Fleet, deployment: InstallerBasedDeployment
) -> None:
    """The installer finished, and the host is configured."""
    installation = deployment.finish(fleet, host)
    if not installation.succeeded:
        pytest.fail(installation.describe(), pytrace=False)


@then(parsers.re(r'the sudo stack of "(?P<name>[^"]+)" asks the portal'))
def sudo_stack_asks_the_portal(name: str, fleet: Fleet) -> None:
    """Elevation on the host goes through the portal."""
    machine = fleet.machine(name)
    content = fleet.read_as_root(machine, SUDO_STACK)
    missing = [
        pattern for pattern in SUDO_STACK_PATTERNS if not _matches(content, pattern)
    ]
    if missing:
        pytest.fail(
            f"{SUDO_STACK} of {name} does not ask the portal for sudo, it "
            f"misses {', '.join(missing)}:\n{content}",
            pytrace=False,
        )
    LOGGER.info("sudo on %s asks the portal", name)


@then(parsers.re(r'the backends accept only the bastion "(?P<bastion>[^"]+)"'))
def backends_accept_only_the_bastion(bastion: str, fleet: Fleet) -> None:
    """Every configured backend lists the id of the bastion, and nothing else.

    The id is read on the bastion itself: it is the name the portal knows
    the bastion by, and what the backends check a hop against. A backend the
    deployment did not configure has no list to read, and is left alone.

    """
    machine = fleet.machine(bastion)
    result = fleet.run_as_root(machine, BASTION_ID)
    if not result.succeeded or not result.stdout.strip():
        pytest.fail(
            f"{BASTION_ID} could not be read on {bastion}: {result.describe()}",
            pytrace=False,
        )
    identifier = result.stdout.strip().splitlines()[-1].strip()
    LOGGER.info("The id of %s is %s", bastion, identifier)

    checked = 0
    for backend in fleet.machines():
        if backend.type is not Role.BACKEND:
            continue
        if not guest_agent.exists(backend.name, ALLOWED_BASTIONS):
            continue
        checked += 1
        content = fleet.read_as_root(backend, ALLOWED_BASTIONS)
        accepted = [
            item.strip() for item in re.split(r"[,\s]+", content) if item.strip()
        ]
        if accepted != [identifier]:
            pytest.fail(
                f"{backend.name} accepts {accepted} instead of the bastion "
                f"{identifier} of the fleet ({ALLOWED_BASTIONS}):\n{content}",
                pytrace=False,
            )
        LOGGER.info("%s accepts only %s", backend.name, identifier)
    if checked == 0:
        pytest.fail(
            f"No backend of the fleet lists the bastions it accepts "
            f"({ALLOWED_BASTIONS}): were they deployed?",
            pytrace=False,
        )


@then(parsers.re(r'the backend "(?P<name>[^"]+)" is enrolled'))
def backend_is_enrolled(name: str, fleet: Fleet) -> None:
    """The host was set up, and knows the bastion of the fleet.

    The allowlist it writes comes from the bastion, read by the play: a
    host that holds it was configured by a play that could become root
    there.

    """
    machine = fleet.machine(name)
    if not guest_agent.exists(machine.name, CONFIG):
        pytest.fail(f"{name} was not configured: it has no {CONFIG}", pytrace=False)
    bastion = next(
        machine for machine in fleet.machines() if machine.type is Role.BASTION
    )
    identifier = fleet.run_as_root(bastion, BASTION_ID).stdout.split()[-1]
    accepted = fleet.read_as_root(machine, ALLOWED_BASTIONS).split()
    if accepted != [identifier]:
        pytest.fail(
            f"{name} accepts {accepted}, not the id {identifier} of {bastion.name}",
            pytrace=False,
        )


@then(parsers.re(r'no process of "(?P<name>[^"]+)" is left on "(?P<host>[\w.-]+)"'))
def no_process_is_left(name: str, host: str, fleet: Fleet) -> None:
    """The machine took down what the closed session left running.

    The hardening turns on logind's own cleanup of a session's processes, so
    a command started with nohup does not outlive the session.

    """
    machine = fleet.machine(host)
    result = fleet.run_as_root(
        machine,
        f"for i in $(seq 1 20); do pgrep -u {name} >/dev/null || exit 0; sleep 1; done;"
        f" pgrep -a -u {name}; exit 1",
    )
    if not result.succeeded:
        pytest.fail(
            f"{host} still runs processes of {name}:\n{result.stdout}", pytrace=False
        )


def _matches(content: str, pattern: str) -> bool:
    return re.search(pattern, content, re.MULTILINE) is not None

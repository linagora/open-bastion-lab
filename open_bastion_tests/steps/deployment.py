"""Steps reading what a deployment left behind, as root.

A fleet in maximum security has no local account left that can elevate, so
these checks do not go through SSH: they ask the QEMU guest agent of the
machines, which runs as root before PAM and sshd. See
:mod:`open_bastion_tests.support.guest_agent`.

"""

from pytest_bdd import parsers, then

import logging
import re

import pytest

from open_bastion_lab.model import Role

from open_bastion_tests.support import guest_agent
from open_bastion_tests.support.fleet import Fleet

LOGGER = logging.getLogger(__name__)

# What the setup scripts write, and what the scenarios read back
SERVICE_KEYS_DROP_IN = "/etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf"
SUDO_STACK = "/etc/pam.d/sudo"
ALLOWED_BASTIONS = "/etc/open-bastion/allowed_bastions"
BASTION_ID = "/usr/bin/ob-bastion-id"

# sshd serves the keys of the service accounts only with both of them
SERVICE_KEYS_PATTERNS = (
    r"^\s*AuthorizedKeysCommand\s+\S*ob-service-account-keys",
    r"^\s*ExposeAuthInfo\s+yes",
)

# The sudo stack of a maximum security host asks the portal, and refuses
# what it does not answer
SUDO_STACK_PATTERNS = (r"pam_openbastion\.so", r"pam_deny\.so")


@then(parsers.re(r'the sudo stack of "(?P<name>[^"]+)" asks the portal'))
def sudo_stack_asks_the_portal(name: str, deployed_fleet: Fleet) -> None:
    """Elevation on the host goes through the portal."""
    machine = deployed_fleet.machine(name)
    content = deployed_fleet.read_as_root(machine, SUDO_STACK)
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
def backends_accept_only_the_bastion(bastion: str, deployed_fleet: Fleet) -> None:
    """Every backend lists the id of the bastion, and nothing else.

    The id is read on the bastion itself: it is the name the portal knows
    the bastion by, and what the backends check a hop against.

    """
    machine = deployed_fleet.machine(bastion)
    result = deployed_fleet.run_as_root(machine, BASTION_ID)
    if not result.succeeded or not result.stdout.strip():
        pytest.fail(
            f"{BASTION_ID} could not be read on {bastion}: {result.describe()}",
            pytrace=False,
        )
    identifier = result.stdout.strip().splitlines()[-1].strip()
    LOGGER.info("The id of %s is %s", bastion, identifier)

    for backend in deployed_fleet.machines():
        if backend.type is not Role.BACKEND:
            continue
        content = deployed_fleet.read_as_root(backend, ALLOWED_BASTIONS)
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


def _matches(content: str, pattern: str) -> bool:
    return re.search(pattern, content, re.MULTILINE) is not None

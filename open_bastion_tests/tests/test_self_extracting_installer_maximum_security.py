"""The maximum security deployment, run from the self-extracting installers."""

from pathlib import Path

import pytest
from pytest_bdd import scenario

from open_bastion_tests.support.installer import InstallerBasedDeployment

FEATURE = "self_extracting_installer_maximum_security.feature"


@pytest.fixture(scope="module")
def deployment(module_dir: Path) -> InstallerBasedDeployment:
    """What the steps of the Background did to the fleet, kept for the feature.

    The fixture holds the state and nothing else: the deployment is the
    Background, step by step, because the keys of the local accounts are
    copied to the machines before anything configures them, and each host's
    enrolment is approved while its installer waits for it.

    """
    return InstallerBasedDeployment(module_dir)


@scenario(FEATURE, "Users known to the portal reach the bastion")
def test_bastion_access() -> None:
    pass


@scenario(FEATURE, "Users known to the portal reach the backend through a bastion")
def test_backend_access() -> None:
    pass


@scenario(FEATURE, "Users not known to the portal can't access the bastion")
def test_local_account() -> None:
    pass


@scenario(FEATURE, "Users not known to the portal can't access the backend")
def test_local_account_on_backend() -> None:
    pass


@scenario(FEATURE, "A user whose access to the backends is removed can't hop")
def test_backend_access_removed() -> None:
    pass


@scenario(FEATURE, "A user whose access is removed can't reach the bastion")
def test_bastion_access_removed() -> None:
    pass


@scenario(FEATURE, "Sudo on the backends follows the rules of the portal")
def test_sudo_on_backends() -> None:
    pass


@scenario(FEATURE, "A user allowed to sudo on the backends can't sudo on the bastion")
def test_sudo_on_bastion() -> None:
    pass


@scenario(FEATURE, "A user whose sudo access is removed can't sudo")
def test_sudo_removed() -> None:
    pass


@scenario(FEATURE, "A service account reach the bastion but can't sudo")
def test_service_account_on_bastion() -> None:
    pass


@scenario(FEATURE, "A service account reach the backends but can't sudo")
def test_service_account_on_backends() -> None:
    pass


@scenario(FEATURE, "Sudo on the bastion goes through the portal")
def test_sudo_goes_through_the_portal() -> None:
    pass


@scenario(FEATURE, "The backends only accept the bastion of the fleet")
def test_backends_accept_only_the_bastion() -> None:
    pass


@scenario(FEATURE, "A revoked certificate is refused once the list is refreshed")
def test_revoked_certificate() -> None:
    pass


@scenario(FEATURE, "The bastion records what a user does on a backend")
def test_session_recording() -> None:
    pass


@scenario(FEATURE, "The cache keeps a user's access while the portal is down")
def test_cache_while_portal_down() -> None:
    pass

"""Sudo on a maximum security fleet: the rules of the portal, and the drop-ins."""

from pytest_bdd import scenario

FEATURE = "sudo_maximum_security.feature"


@scenario(FEATURE, "Sudo on the backends follows the rules of the portal")
def test_sudo_on_backends() -> None:
    pass


@scenario(FEATURE, "An SSO user privileges can be limited")
def test_sudoers_drop_in() -> None:
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

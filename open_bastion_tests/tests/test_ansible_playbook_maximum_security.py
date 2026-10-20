"""The playbook of the maximum security deployment, played on the fleet."""

import pytest
from pytest_bdd import scenario

from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import Llng

FEATURE = "ansible_playbook_maximum_security.feature"

# What the Background of the feature names, and what its scenarios run
# against. pytest needs them before the scenario starts, so they are given
# here as well as in the feature.
FLEET = "two-backends"
LLNG_CONFIG = data("llng/with-two-oidc-rp/lmConf-with-plugins-configured.json")

pytestmark = [
    pytest.mark.parametrize("fleet", [FLEET], indirect=True),
    pytest.mark.parametrize(
        "llng", [LLNG_CONFIG], indirect=True, ids=[LLNG_CONFIG.stem]
    ),
]


@pytest.fixture(autouse=True)
def scenario_setup(fresh_fleet: Fleet, llng: Llng) -> None:
    """Ask for the fleet and the portal before every scenario.

    Both are parametrized, and pytest binds a parametrized fixture to a
    test only when the test asks for it while it is collected: a step
    asking for them once the scenario is running comes too late. The
    feature keeps them from one scenario to the next.

    """


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


@scenario(FEATURE, "The bastion serves the service-account keys")
def test_service_account_keys_are_served() -> None:
    pass


@scenario(FEATURE, "Sudo on the bastion goes through the portal")
def test_sudo_goes_through_the_portal() -> None:
    pass


@scenario(FEATURE, "The backends only accept the bastion of the fleet")
def test_backends_accept_only_the_bastion() -> None:
    pass

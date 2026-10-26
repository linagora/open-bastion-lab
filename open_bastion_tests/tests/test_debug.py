"""A lab configured and kept for debugging."""

import pytest
from pytest_bdd import scenario

from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import Llng
from open_bastion_tests.support.playbook import Administrator

FEATURE = "debug.feature"

FLEET = "three-backends"
CONFIGURATION = "ob-builder-max-security"
LLNG_CONFIG = data("llng/with-two-oidc-rp/lmConf-with-plugins-configured.json")

pytestmark = [
    pytest.mark.debug,
    pytest.mark.parametrize("fleet", [FLEET], indirect=True),
    pytest.mark.parametrize("configuration", [CONFIGURATION], indirect=True),
    pytest.mark.parametrize(
        "llng", [LLNG_CONFIG], indirect=True, ids=[LLNG_CONFIG.stem]
    ),
]


@pytest.fixture(autouse=True)
def scenario_setup(
    fresh_fleet: Fleet, llng: Llng, administrator: Administrator
) -> None:
    """Ask for everything the feature parametrizes, before the scenario.

    The fleet, the portal and the configuration ob-builder builds with are
    parametrized, and pytest binds a parametrized fixture to a test only
    when the test asks for it while it is collected: a step asking for them
    once the scenario is running comes too late. The feature keeps them from
    one scenario to the next.

    """


@scenario(FEATURE, "The lab is configured")
def test_debug_lab() -> None:
    pass

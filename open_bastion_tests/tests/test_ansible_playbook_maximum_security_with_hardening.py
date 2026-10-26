"""The playbook of the maximum security deployment, with hardening on."""

import pytest
from pytest_bdd import scenario

from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import Llng
from open_bastion_tests.support.playbook import Administrator

FEATURE = "ansible_playbook_maximum_security_with_hardening.feature"

FLEET = "three-backends"
CONFIGURATION = "ob-builder-max-security-with-hardening"
LLNG_CONFIG = data("llng/with-two-oidc-rp/lmConf-with-plugins-configured.json")

pytestmark = [
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
    """Ask for everything the feature parametrizes, before every scenario."""


@scenario(
    FEATURE, "A command left running is recorded and does not outlive the session"
)
def test_recording_and_containment() -> None:
    pass

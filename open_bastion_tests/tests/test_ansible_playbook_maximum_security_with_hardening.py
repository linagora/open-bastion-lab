"""The playbook of the maximum security deployment, with hardening on."""

from pytest_bdd import scenario

FEATURE = "ansible_playbook_maximum_security_with_hardening.feature"


@scenario(
    FEATURE, "A command left running is recorded and does not outlive the session"
)
def test_recording_and_containment() -> None:
    pass

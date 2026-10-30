"""The playbook of the maximum security deployment, played on the fleet."""

from pytest_bdd import scenario

FEATURE = "ansible_playbook_maximum_security.feature"


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


@scenario(FEATURE, "SSO users can play a second playbook")
def test_second_playbook_by_an_sso_user() -> None:
    pass


@scenario(FEATURE, "Non-SSO users can't play a second playbook")
def test_second_playbook_by_a_service_account() -> None:
    pass


@scenario(
    FEATURE, "Playing the tree again as an SSO user leaves the configuration alone"
)
def test_second_playbook_keeps_the_configuration() -> None:
    pass


@scenario(FEATURE, "The bastion records what a user does on a backend")
def test_session_recording() -> None:
    pass


@scenario(FEATURE, "The cache keeps a user's access while the portal is down")
def test_cache_while_portal_down() -> None:
    pass

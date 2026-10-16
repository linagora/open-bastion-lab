"""Steps related to SSH access."""

from collections.abc import Callable
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, then, when

from open_bastion_tests.support.fleet import Fleet
from open_bastion_tests.support.llng import Llng, Session
from open_bastion_tests.support.playbook import Administrator
from open_bastion_tests.support.ssh import Connection, HopResult, SshResult, User


@given(parsers.re(r'the fleet "(?P<name>[^"]+)" is ready'))
def fleet_is_ready(name: str, fresh_fleet: Fleet) -> None:
    """The machines are created, booted, and given back to the feature.

    Naming the fleet in the feature says which one the scenarios run
    against; the module of the feature says the same, because pytest needs
    it before the scenario starts, and this step is where the two meet.

    """
    if fresh_fleet.name != name:
        pytest.fail(
            f"The feature names the fleet {name}, but the tests run against "
            f"{fresh_fleet.name}"
        )


@given(parsers.re(r'the portal loaded the "(?P<name>[^"]+)" configuration'))
def portal_loaded_configuration(name: str, llng: Llng) -> None:
    """The portal runs the named configuration, imported by the fixture.

    Same meeting point as for the fleet: the feature names the
    configuration, the module of the feature gives it to the fixture.

    """
    if llng.configuration != name:
        pytest.fail(
            f"The feature names the configuration {name}, but the portal runs "
            f"{llng.configuration}"
        )


@given(
    parsers.re(
        r"an administrator runs ob-builder to generate an ansible playbook "
        r'with the "(?P<name>[^"]+)" configuration'
    )
)
def administrator_generates_playbook(
    name: str, playbook: Path, administrator: Administrator
) -> None:
    """ob-builder is run by the fixture, once for the feature.

    Naming the configuration in the feature says which deployment the
    scenarios describe, and this is where that name meets the one the
    administrator builds with. ob-builder reads the SSO metadata, the SSH
    CA key and the revocation list from the portal while building, so the
    portal has to be up.

    """
    if administrator.configuration != name:
        pytest.fail(
            f"The feature names the configuration {name}, but ob-builder "
            f"builds with {administrator.configuration}"
        )
    assert playbook.is_file()


@given("the administrator plays the generated playbook against the fleet")
def administrator_plays_playbook(deployed_fleet: Fleet) -> None:
    """The play is run by the fixture, once for the feature."""


@given(
    parsers.parse("user {name} has signed its SSH public key"),
    target_fixture="user",
)
def user_signs_its_public_key(
    name: str,
    user_factory: Callable[[str], User],
    portal_sessions: Callable[[str], Session | None],
    llng: Llng,
    scenario_dir: Path,
) -> User:
    """Give the user a key pair, signed by the portal.

    A user the portal does not know cannot be given a certificate, and the
    scenarios asking for a signature are about users it knows: failing is
    better than letting them run without one.

    """
    user = user_factory(name)
    user.generate_key()

    session = portal_sessions(name)
    if session is None:
        pytest.fail(f"{name} has no session on the portal, there is no key to sign")
    certificate = llng.sign(
        session,
        user.public_key(),
        f"{user.name} {user.fingerprint()}",
        scenario_dir / "llng" / f"sign-{name}.json",
    )
    user.save_certificate(certificate)
    return user


@given(
    parsers.re(
        r'user "(?P<name>[^"]+)" has copied its SSH public key to "(?P<host>[^"]+)"'
    ),
    target_fixture="user",
)
def user_copies_its_public_key(
    name: str,
    host: str,
    copied_public_keys: Callable[[str, str], User],
) -> User:
    """Leave the key of a local account on a machine, as its owner would.

    The copy is made by the fixture of the feature, once, while the
    machines still accept the password of their accounts: what they do with
    that key once configured is what the scenarios ask.

    """
    return copied_public_keys(name, host)


@given("the administrator set pam-access SSH rule to:")
def administrator_sets_pam_access_ssh_rule(
    datatable: list[list[str]],
    llng: Llng,
    fresh_fleet: Fleet,
) -> None:
    """Give the portal the SSH rules of the table, one row per server group.

    A row replaces the rule of its group, the rules of the groups the table
    does not name are left as they are. The machines keep the answers of the
    portal for a minute, so their cache is dropped as well: it is what makes
    the change immediate instead of waiting for the next query.

    """
    rules = {group: rule for group, rule in datatable}
    llng.set_pam_ssh_rules(rules)
    fresh_fleet.forget_authorizations()


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? tries to connect to "(?P<host>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_connects(name: str, host: str, user: User, user_ssh_config: Path) -> SshResult:
    return user.connect(host, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? hops from "(?P<bastion>[\w.-]+)" '
        r'to "(?P<backend>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_hops(
    name: str, bastion: str, backend: str, user: User, user_ssh_config: Path
) -> HopResult:
    """Open a session on the bastion, and reach the backend from there.

    A backend only accepts the certificates a bastion vouches for, so a
    hop is the way the fleet intends a user to reach one.

    """
    return user.hop(bastion, backend, user_ssh_config)


@then(parsers.parse("the result is {expected}"))
def result_is(connection: Connection, expected: str) -> None:
    if expected == "success":
        assert connection.succeeded, connection.describe()
    else:
        assert connection.denied, connection.describe()

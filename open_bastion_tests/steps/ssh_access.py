"""Steps related to SSH access."""

from collections.abc import Callable
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, then, when

from open_bastion_tests.support.fleet import (
    AUTHORIZATION_CACHE,
    Fleet,
    authorization_entry,
)
from open_bastion_tests.support.llng import Llng, Session
from open_bastion_tests.support.playbook import Administrator
from open_bastion_tests.support.ssh import (
    Connection,
    HopResult,
    ServiceAccount,
    SshResult,
    SudoResult,
    User,
)


@given(parsers.re(r'the fleet "(?P<name>[^"]+)" is ready'))
def fleet_is_ready(name: str, fresh_fleet: Fleet) -> None:
    """The machines are created, booted, and given back to the feature.

    Naming the fleet in the feature says which one the scenarios run
    against; the module of the feature says the same, because pytest needs
    it before the scenario starts, and this step is where the two meet.

    The SSH authorization cache is cleared on each machine of the
    fleet.

    """
    if fresh_fleet.name != name:
        pytest.fail(
            f"The feature names the fleet {name}, but the tests run against "
            f"{fresh_fleet.name}"
        )
    fresh_fleet.forget_authorizations()


@given(parsers.re(r'the LLNG configuration is "(?P<name>[^"]+)"'))
def llng_configuration_is(name: str, llng: Llng) -> None:
    """The portal runs the configuration the feature names, whatever ran before.

    The module of the feature gives the fixture the file, the feature names
    it, and this is where the two meet. A scenario that changes the
    configuration does not depend on the order it runs in: the file is
    imported again when an earlier scenario changed it.

    """
    if llng.configuration != name:
        pytest.fail(
            f"The feature names the configuration {name}, but the portal runs "
            f"{llng.configuration}"
        )
    llng.ensure_configuration()


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
    # The name may be quoted in the feature: a parse expression would keep
    # the quotes, and the portal would be asked about a user called
    # '"rtyler"', which it does not know.
    parsers.re(r'user "?(?P<name>[\w.-]+)"? has signed its SSH public key'),
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
    user.ensure_key()

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
) -> None:
    """Give the portal the SSH rules of the table, one row per server group.

    A row replaces the rule of its group, the rules of the groups the table
    does not name are left as they are. Neither the workers of the portal
    nor the machines know the change yet: a scenario that expects it to be
    immediate says so with the steps that follow.

    """
    rules = {group: rule for group, rule in datatable}
    llng.set_pam_ssh_rules(rules)


@given("the administrator set pam-access sudo rule to:")
def administrator_sets_pam_access_sudo_rule(
    datatable: list[list[str]],
    llng: Llng,
) -> None:
    """Give the portal the sudo rules of the table, one row per server group.

    Same as the SSH rules: neither the workers of the portal nor the
    machines know the change yet.

    """
    rules = {group: rule for group, rule in datatable}
    llng.set_pam_sudo_rules(rules)


@given("the portal workers reloaded the configuration")
def portal_workers_reload_configuration(llng: Llng) -> None:
    """Make every worker serve the rule the scenario just set.

    A worker reads the configuration cache on a timer of its own, so a
    change can take a minute to reach all of them: the portal is restarted,
    which has them all load the current configuration at once.

    """
    llng.reload()


@given("the administrator drops the authorization cache of the fleet")
def administrator_drops_authorization_cache(fresh_fleet: Fleet) -> None:
    """Make the machines ask the portal again.

    They cache the authorization answers for a minute, so without this the
    rule a scenario just set may not be known when the next connection
    asks. Dropping the cache is a scenario step: what the machines know
    and when they learn it is part of what the scenarios are about.

    """
    fresh_fleet.forget_authorizations()


@when("the portal is down")
def portal_is_down(portal_down: None) -> None:
    """The portal is stopped by the fixture, and started again after it.

    A machine answers from what it cached once the portal is away, which
    is what the steps that follow ask about.

    """


@then(
    parsers.re(
        r'the authorization of "(?P<name>[^"]+)" is cached on "(?P<host>[\w.-]+)"'
    )
)
def authorization_is_cached(name: str, host: str, deployed_fleet: Fleet) -> None:
    """The machine kept the answer the portal gave for the user.

    What is cached is the authorization, not the key: the entry holds the
    groups of the user and what it may do with sudo, and sshd validates the
    certificate on its own before PAM is asked.

    """
    machine = deployed_fleet.machine(host)
    if not deployed_fleet.cached_authorization(machine, name):
        listing = deployed_fleet.run_as_root(
            machine, f"ls -l {AUTHORIZATION_CACHE}"
        ).stdout
        pytest.fail(
            f"{host} holds no authorization for {name}: expected "
            f"{authorization_entry(machine, name)}.\n{listing}",
            pytrace=False,
        )


@when(
    parsers.re(
        r'the authorization of "(?P<name>[^"]+)" is removed from "(?P<host>[\w.-]+)"'
    )
)
def authorization_is_removed(name: str, host: str, deployed_fleet: Fleet) -> None:
    """Drop the entry, as the time to live of the cache would."""
    deployed_fleet.forget_authorization(deployed_fleet.machine(host), name)


@then("the hop cannot be made")
def hop_cannot_be_made(connection: HopResult) -> None:
    """The bastion could not vouch for the user.

    ob-ssh mints a certificate through the portal for every hop, and
    nothing there is cacheable: a backend whose authorization is cached
    still cannot be reached while the portal is away. The backend did not
    refuse anything, so this is not read as a refusal.

    """
    assert not connection.succeeded, connection.describe()


@when(
    parsers.re(
        r'service account "(?P<name>[^"]+)" tries to connect to "(?P<host>[\w.-]+)" '
        r"through SSH"
    ),
    target_fixture="connection",
)
def service_account_connects(
    name: str,
    host: str,
    deployed_fleet: Fleet,
    service_account: Callable[[str], ServiceAccount],
) -> SshResult:
    """Try the key the deployment serves for the account.

    sshd serves it from the configuration ob-builder was given, so the
    machine lets the account in on its own: no session, no certificate and
    no portal are involved.

    """
    return service_account(name).connect(deployed_fleet.machine(host))


@when(
    parsers.re(
        r'service account "(?P<name>[^"]+)" runs sudo on "(?P<host>[\w.-]+)" '
        r"through SSH"
    ),
    target_fixture="connection",
)
def service_account_runs_sudo(
    name: str,
    host: str,
    deployed_fleet: Fleet,
    service_account: Callable[[str], ServiceAccount],
) -> SudoResult:
    """Try to elevate as the account, with nothing to give sudo.

    The account has no session on the portal, so the PAM stack of a
    configured machine has nothing to check the elevation against.

    """
    return service_account(name).sudo(deployed_fleet.machine(host))


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


@given(
    parsers.re(r'user "?(?P<name>[\w.-]+)"? has a temporary token from the portal'),
    target_fixture="token",
)
def user_has_a_temporary_token(
    name: str,
    user: User,
    portal_sessions: Callable[[str], Session | None],
    llng: Llng,
) -> str:
    """Get the one-time token sudo asks as a password.

    The portal hands it to a signed-in session, and the PAM stack of the
    machines consumes it at the first use.

    """
    if user.name != name:
        pytest.fail(f"The feature names {name}, but the user is {user.name}")
    session = portal_sessions(name)
    if session is None:
        pytest.fail(f"{name} has no session on the portal, there is no token to give")
    return llng.pam_token(session)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs sudo on "(?P<host>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_sudo(
    name: str, host: str, user: User, token: str, user_ssh_config: Path
) -> SudoResult:
    """Open a session on the machine and try to elevate there."""
    return user.sudo(host, token, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs sudo on "(?P<backend>[\w.-]+)" '
        r'from "(?P<bastion>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_sudo_from(
    name: str,
    backend: str,
    bastion: str,
    user: User,
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Open a session on the bastion and try to elevate on the backend."""
    return user.sudo_from(bastion, backend, token, user_ssh_config)


@then(parsers.parse("the result is {expected}"))
def result_is(connection: Connection, expected: str) -> None:
    if expected == "success":
        assert connection.succeeded, connection.describe()
    else:
        assert connection.denied, connection.describe()

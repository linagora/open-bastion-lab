"""Steps related to SSH access."""

import re
import shlex
from collections.abc import Callable
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, then, when

from open_bastion_lab.model import Role

from open_bastion_tests.support.fleet import (
    AUTHORIZATION_CACHE,
    Fleet,
    Labs,
    authorization_entry,
)
from open_bastion_tests.support.llng import Llng, Session
from open_bastion_tests.support.deployment import (
    Administrator,
    Play,
    inventory_for,
    llng_configuration,
)
from open_bastion_tests.support.ssh import (
    ChannelResult,
    Connection,
    FORWARDING_REFUSED,
    HopResult,
    ServiceAccount,
    SshResult,
    SudoResult,
    User,
    revocation_list,
)

CA_KEY = "/etc/ssh/open-bastion_ca.pub"
SESSIONS = "/var/lib/open-bastion/sessions"
# What the service a channel forwards to serves, and what it is started from.
SERVICE_ROOT = "/srv/ob-lab-forwarding"

# What sudo prints when its policy has no entry for the command it was given.
POLICY_REFUSED = "is not allowed to execute"

# A line of the rules a step declares: the server group, then the expression.
RULE_LINE = re.compile(r"^(?P<group>[\w.-]+)\s*:\s*(?P<rule>.+)$")

# What sudo prints when it has nothing to authenticate a user with.
PASSWORD_REQUIRED = "a password is required"


@given(parsers.re(r'the fleet "(?P<name>[^"]+)" is ready'), target_fixture="fleet")
def fleet_is_ready(name: str, labs: Labs, request: pytest.FixtureRequest) -> Fleet:
    """The machines the feature names, restored for it.

    The fleet a feature runs against is the one its Background names: it is
    created the first time a feature asks for it, and every feature starts
    its machines from the snapshot taken then. The authorization cache is
    cleared, so what an earlier feature cached is not what a scenario reads.

    """
    try:
        fleet = labs.ready(name, feature=request.module.__name__)
    except RuntimeError as error:
        pytest.fail(str(error), pytrace=False)
    fleet.forget_authorizations()
    return fleet


@given(parsers.re(r'the LLNG configuration is "(?P<name>[^"]+)"'))
def llng_configuration_is(name: str, llng: Llng) -> None:
    """The portal runs the configuration the feature names.

    A scenario may change the configuration, and a feature does not decide
    the order its scenarios run in: the file is imported again once the
    portal drifted.

    """
    configuration = llng_configuration(name)
    if llng.config_file is None or llng.configuration != name:
        llng.restore(configuration)
    else:
        llng.ensure_configuration()


@given(
    parsers.re(
        r'the administrator generates the playbook with the "(?P<name>[^"]+)" configuration'
    ),
    target_fixture="playbook",
)
def administrator_generates_playbook(name: str, administrator: Administrator) -> Path:
    """ob-builder writes the tree of the configuration, once for the feature.

    ob-builder reads the SSO metadata, the SSH CA key and the revocation
    list from the portal while building, so the portal has to be up.

    """
    playbook = administrator.generate_playbook(name)
    assert playbook.is_file()
    return playbook


@given(
    parsers.re(
        r"the administrator plays the generated playbook against the fleet"
        r"(?:, (?P<excluded>[\w.-]+) excluded)?"
    )
)
def administrator_plays_playbook(
    fleet: Fleet,
    playbook: Path,
    administrator: Administrator,
    portal_session: Session,
    excluded: str | None = None,
) -> None:
    """The play is run once for the feature, on the hosts it keeps.

    A host the feature leaves out is outside the limit, and stays
    unconfigured; a host it keeps is deployed and enrolled.

    """
    hosts = [machine.name for machine in fleet.machines() if machine.name != excluded]
    play = administrator.play_once(
        fleet, portal_session, inventory_for(fleet), limit=",".join(hosts)
    )
    if not play.succeeded:
        raise RuntimeError(play.describe())


@when(
    parsers.re(
        r'the administrator plays the playbook again as "(?P<name>[^"]+)" '
        r'for "(?P<host>[\w.-]+)"'
    ),
    target_fixture="play",
)
def administrator_plays_again(
    name: str,
    host: str,
    administrator: Administrator,
    fleet: Fleet,
    user_factory: Callable[[str], User],
    portal_sessions: Callable[[str], Session | None],
) -> Play:
    """Play the tree again as an SSO user, for one machine of the fleet."""
    session = portal_sessions(name)
    if session is None:
        pytest.fail(f"{name} has no session on the portal, there is no token to mint")
    return administrator.play_playbook(
        fleet,
        session,
        inventory_for(fleet),
        as_user=user_factory(name),
        limit=host,
    )


@when(
    parsers.re(
        r'the administrator plays the playbook again for "(?P<host>[\w.-]+)" '
        r"as a service account"
    ),
    target_fixture="play",
)
def administrator_plays_as_service_account(
    host: str,
    administrator: Administrator,
    fleet: Fleet,
    portal_session: Session,
) -> Play:
    """Play the tree again as the account the inventory names."""
    return administrator.play_playbook(
        fleet, portal_session, inventory_for(fleet), limit=host
    )


@then("the play succeeds")
def play_succeeds(play: Play) -> None:
    assert play.succeeded, play.describe()


@then(parsers.re(r'the play warns that "(?P<host>[\w.-]+)" keeps its SSO sudo'))
def play_warns_locked(host: str, play: Play) -> None:
    """The role said why it left the host alone, instead of doing nothing."""
    if (
        f"{host} runs maximum security: its sudo only takes SSO tokens"
        not in play.text()
    ):
        pytest.fail(
            f"The play left {host} alone without saying why: {play.describe()}",
            pytrace=False,
        )


@then(parsers.re(r'the play changed nothing on "(?P<host>[\w.-]+)"'))
def play_changed_nothing(host: str, play: Play) -> None:
    """The host was left as it was: the play could not become root there."""
    counters = play.recap(host)
    if counters.get("changed", 1) != 0:
        pytest.fail(
            f"The play changed {counters.get('changed', 'an unknown number of')} "
            f"on {host}: {play.describe()}",
            pytrace=False,
        )


@given(
    # The name may be quoted in the feature: a parse expression would keep
    # the quotes, and the portal would be asked about a user called
    # '"rtyler"', which it does not know.
    parsers.re(r'user "?(?P<name>[\w.-]+)"? has signed its SSH public key'),
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
)
def user_copies_its_public_key(
    name: str,
    host: str,
    fleet: Fleet,
    copied_public_keys: Callable[[str, str, Fleet], User],
) -> User:
    """Leave the key of a local account on a machine, as its owner would.

    The copy is made by the fixture of the feature, once, while the
    machines still accept the password of their accounts: what they do with
    that key once configured is what the scenarios ask.

    """
    return copied_public_keys(name, host, fleet)


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


@then("the pam-access ssh rules are")
def pam_access_ssh_rules_are(docstring: str, llng: Llng) -> None:
    """The portal decides who may reach each server group, as the step says.

    One line per group, "group: rule", the rule being the expression the
    portal evaluates. A feature states them in its Background so a reader
    has what its scenarios rest on in front of it, and a portal that drifted
    fails here rather than in a scenario that happens to need a rule.

    """
    _rules_are("ssh", docstring, llng.pam_ssh_rules())


@then("the pam-access sudo rules are")
def pam_access_sudo_rules_are(docstring: str, llng: Llng) -> None:
    """The portal decides who may elevate on each server group, as the step says.

    Same as the SSH rules: the lines are the ones the scenarios rest on.

    """
    _rules_are("sudo", docstring, llng.pam_sudo_rules())


def _rules_are(kind: str, docstring: str, actual: dict[str, str]) -> None:
    """The rules of the portal are the ones the step declares."""
    declared: dict[str, str] = {}
    for line in docstring.splitlines():
        if not line.strip():
            continue
        match = RULE_LINE.match(line.strip())
        if match is None:
            pytest.fail(f"The step reads 'group: rule', not {line!r}", pytrace=False)
        declared[match["group"]] = match["rule"]

    drifted = [
        f"{group} is {actual.get(group)!r} instead of {rule!r}"
        for group, rule in declared.items()
        if actual.get(group) != rule
    ]
    if drifted:
        pytest.fail(
            f"The {kind} rules of the portal are not the ones the feature "
            "declares: " + "; ".join(drifted),
            pytrace=False,
        )


@given("the portal workers reloaded the configuration")
def portal_workers_reload_configuration(llng: Llng) -> None:
    """Make every worker serve the rule the scenario just set.

    A worker reads the configuration cache on a timer of its own, so a
    change can take a minute to reach all of them: the portal is restarted,
    which has them all load the current configuration at once.

    """
    llng.reload()


@given("the administrator drops the authorization cache of the fleet")
def administrator_drops_authorization_cache(fleet: Fleet) -> None:
    """Make the machines ask the portal again.

    They cache the authorization answers for a minute, so without this the
    rule a scenario just set may not be known when the next connection
    asks. Dropping the cache is a scenario step: what the machines know
    and when they learn it is part of what the scenarios are about.

    """
    fleet.forget_authorizations()


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
def authorization_is_cached(name: str, host: str, fleet: Fleet) -> None:
    """The machine kept the answer the portal gave for the user.

    What is cached is the authorization, not the key: the entry holds the
    groups of the user and what it may do with sudo, and sshd validates the
    certificate on its own before PAM is asked.

    """
    machine = fleet.machine(host)
    if not fleet.cached_authorization(machine, name):
        listing = fleet.run_as_root(machine, f"ls -l {AUTHORIZATION_CACHE}").stdout
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
def authorization_is_removed(name: str, host: str, fleet: Fleet) -> None:
    """Drop the entry, as the time to live of the cache would."""
    fleet.forget_authorization(fleet.machine(host), name)


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
    fleet: Fleet,
    service_account: Callable[[str], ServiceAccount],
) -> SshResult:
    """Try the key the deployment serves for the account.

    sshd serves it from the configuration ob-builder was given, so the
    machine lets the account in on its own: no session, no certificate and
    no portal are involved.

    """
    return service_account(name).connect(fleet.machine(host))


@given(
    parsers.re(
        r'the administrator added "(?P<name>[^"]+)" to the group "(?P<group>[^"]+)" '
        r'of "(?P<host>[\w.-]+)"'
    )
)
def administrator_adds_to_the_group(
    name: str, group: str, host: str, fleet: Fleet
) -> None:
    """Add a local account to a group of a machine, as an administrator would.

    A configured fleet has no sudo left for a local account, so the guest
    agent is what runs usermod; the group the account landed in is read back,
    because it is the grant the scenario talks about.

    """
    machine = fleet.machine(host)
    added = fleet.run_as_root(machine, f"usermod -aG {group} {name}")
    if not added.succeeded:
        pytest.fail(
            f"Could not add {name} to {group} on {host}: {added.describe()}",
            pytrace=False,
        )
    listing = fleet.run_as_root(machine, f"getent group {group}").stdout.strip()
    members = [member.strip() for member in listing.rsplit(":", 1)[-1].split(",")]
    if name not in members:
        pytest.fail(
            f"{group} on {host} does not list {name}: {listing!r}", pytrace=False
        )


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
    fleet: Fleet,
    service_account: Callable[[str], ServiceAccount],
) -> SudoResult:
    """Try to elevate as the account, with nothing to give sudo.

    The account has no session on the portal, so the PAM stack of a
    configured machine has nothing to check the elevation against.

    """
    return service_account(name).sudo(fleet.machine(host))


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? tries to connect to "(?P<host>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_connects(
    name: str,
    host: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> SshResult:
    return user_factory(name).connect(host, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? hops from "(?P<bastion>[\w.-]+)" '
        r'to "(?P<backend>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_hops(
    name: str,
    bastion: str,
    backend: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> HopResult:
    """Open a session on the bastion, and reach the backend from there.

    A backend only accepts the certificates a bastion vouches for, so a
    hop is the way the fleet intends a user to reach one.

    """
    return user_factory(name).hop(bastion, backend, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? hops from "(?P<bastion>[\w.-]+)" '
        r'to "(?P<backend>[\w.-]+)" through SSH and runs'
    ),
    target_fixture="connection",
)
def user_hops_and_runs(
    name: str,
    bastion: str,
    backend: str,
    docstring: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> HopResult:
    """Reach the backend and run the commands the step carries.

    They come as its docstring, one per line, and reach the backend as
    one script: its shell expands what they contain, as it would for a
    person typing them into the session.

    """
    return user_factory(name).hop(bastion, backend, user_ssh_config, docstring)


@given(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? writes the sudoers file "(?P<path>[^"]+)" '
        r'on "(?P<host>[\w.-]+)" from "(?P<bastion>[\w.-]+)"'
    ),
    target_fixture="connection",
)
def user_writes_sudoers_file(
    name: str,
    path: str,
    host: str,
    bastion: str,
    docstring: str,
    token: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> HopResult:
    """Leave a root-owned file on a backend, as the step's docstring reads.

    The content is staged in the temporary directory of the machine, then
    installed with the mode sudoers expects of a drop-in; the token of the
    portal is what sudo asks for, once.

    """
    staged = f"/tmp/{Path(path).name}"
    script = "\n".join(
        [
            "umask 077",
            f"cat > {staged} <<'CONTENT'",
            docstring,
            "CONTENT",
            f"echo {token} | sudo -S install -m 0440 -o root -g root {staged} {path}",
            f"rm -f {staged}",
        ]
    )
    connection = user_factory(name).hop(bastion, host, user_ssh_config, script)
    if not connection.succeeded:
        pytest.fail(
            f"{name} could not write {path} on {host}: {connection.describe()}",
            pytrace=False,
        )
    return connection


@then(
    parsers.re(r'the recording of "(?P<name>[^"]+)" on "(?P<bastion>[\w.-]+)" holds:')
)
def recording_holds(
    name: str,
    bastion: str,
    datatable: list[list[str]],
    fleet: Fleet,
) -> None:
    """What the session printed is in the recordings of the bastion."""
    machine = fleet.machine(bastion)
    recordings = fleet.run_as_root(machine, f"cat {SESSIONS}/{name}/*.typescript")
    if not recordings.succeeded:
        pytest.fail(
            f"{bastion} recorded no session of {name}: {recordings.describe()}",
            pytrace=False,
        )
    missing = [row[0] for row in datatable if row[0] not in recordings.stdout]
    if missing:
        pytest.fail(
            f"The recording of {name} on {bastion} does not hold {missing}:\n"
            f"{recordings.stdout[-2000:]}",
            pytrace=False,
        )


@given(
    parsers.re(r'user "?(?P<name>[\w.-]+)"? has a temporary token from the portal'),
    target_fixture="token",
)
def user_has_a_temporary_token(
    name: str,
    portal_sessions: Callable[[str], Session | None],
    llng: Llng,
) -> str:
    """Get the one-time token sudo asks as a password.

    The portal hands it to a signed-in session, and the PAM stack of the
    machines consumes it at the first use.

    """
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
    name: str,
    host: str,
    user_factory: Callable[[str], User],
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Open a session on the machine and try to elevate there."""
    return user_factory(name).sudo(host, token, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs sudo "(?P<command>[^"]+)" '
        r'on "(?P<host>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_sudo_command(
    name: str,
    command: str,
    host: str,
    user_factory: Callable[[str], User],
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Run one command through sudo, with the token of the portal."""
    return user_factory(name).sudo_command(host, command, token, user_ssh_config)


@given(parsers.re(r'the administrator revokes the certificate of "(?P<name>[^"]+)"'))
def administrator_revokes_certificate(
    name: str,
    user_factory: Callable[[str], User],
    fleet: Fleet,
    llng: Llng,
    scenario_dir: Path,
) -> None:
    """Publish on the portal a list that revokes the certificate of the user."""
    bastion = next(
        machine for machine in fleet.machines() if machine.type is Role.BASTION
    )
    ca_key = scenario_dir / "open-bastion_ca.pub"
    ca_key.write_text(fleet.read_as_root(bastion, CA_KEY))
    krl = revocation_list(
        user_factory(name).certificate, ca_key, scenario_dir / "revoked_keys"
    )
    llng.publish_revocation_list(krl)


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
    user_factory: Callable[[str], User],
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Open a session on the bastion and try to elevate on the backend."""
    return user_factory(name).sudo_from(bastion, backend, token, user_ssh_config)


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs with sudo on "(?P<backend>[\w.-]+)" '
        r'from "(?P<bastion>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_with_sudo_from(
    name: str,
    backend: str,
    bastion: str,
    docstring: str,
    user_factory: Callable[[str], User],
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Run the command the step carries through sudo on a backend.

    The command comes as its docstring, which keeps it in the scenario; sudo
    runs it with the one-time token of the portal, as it would ask for it.

    """
    command = docstring.strip()
    if "\n" in command:
        pytest.fail(
            f"The step runs one command, not a script: {command!r}", pytrace=False
        )
    return user_factory(name).sudo_command_from(
        bastion, backend, command, user_ssh_config, token
    )


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs with sudo, without a token, '
        r'on "(?P<backend>[\w.-]+)" from "(?P<bastion>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_without_a_token(
    name: str,
    backend: str,
    bastion: str,
    docstring: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> SudoResult:
    """Run the command of the step through sudo with nothing to give it.

    sudo is told to ask nothing, so what it answers is what its own policy
    and the PAM stack of the host decide. An elevation the user cached
    earlier answers instead: a scenario that asks this question drops it
    first, with a step of its own.

    """
    command = docstring.strip()
    if "\n" in command:
        pytest.fail(
            f"The step runs one command, not a script: {command!r}", pytrace=False
        )
    return user_factory(name).sudo_command_from(
        bastion, backend, command, user_ssh_config
    )


@then("the refusal comes from the sudoers policy")
def refusal_comes_from_the_sudoers_policy(connection: SudoResult) -> None:
    """sudo read its policy and turned the command down before PAM was asked.

    A token the fleet no longer accepts fails at the prompt and says so:
    reading the message is what tells a command sudoers never allowed from
    an elevation the portal refused.

    """
    if POLICY_REFUSED not in connection.output:
        pytest.fail(
            f"sudo did not refuse the command from its policy: {connection.describe()}",
            pytrace=False,
        )


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? drops its cached sudo '
        r'on "(?P<backend>[\w.-]+)" from "(?P<bastion>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_drops_its_cached_sudo(
    name: str,
    backend: str,
    bastion: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> SudoResult:
    """Have sudo forget the elevation the user got on the backend earlier.

    sudo keeps such a timestamp for a quarter of an hour by default, and
    arms it at every use, so a scenario that asks what sudo does without a
    password has to drop it. It is a step of its own so the feature says it.

    """
    connection = user_factory(name).drop_sudo_cache(bastion, backend, user_ssh_config)
    if not connection.succeeded:
        pytest.fail(
            f"{name} could not drop its cached sudo on {backend}: "
            f"{connection.describe()}",
            pytrace=False,
        )
    return connection


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? runs with sudo on "(?P<host>[\w.-]+)" through SSH'
    ),
    target_fixture="connection",
)
def user_runs_with_sudo(
    name: str,
    host: str,
    docstring: str,
    user_factory: Callable[[str], User],
    token: str,
    user_ssh_config: Path,
) -> SudoResult:
    """Run the command the step carries through sudo on the machine it names.

    The machine is the one the user connects to, not one reached from a
    bastion: the bastion of the fleet is such a machine.

    """
    command = docstring.strip()
    if "\n" in command:
        pytest.fail(
            f"The step runs one command, not a script: {command!r}", pytrace=False
        )
    return user_factory(name).sudo_command(host, command, token, user_ssh_config)


@then("the refusal comes from the password stage")
def refusal_comes_from_the_password_stage(connection: SudoResult) -> None:
    """sudo had nothing to authenticate the user with, and said so.

    The command the user asked for is granted — the group the sudoers rule
    names holds it — so the elevation reached the PAM stack and stopped
    there: only the portal can hand sudo what it asks for.

    """
    if PASSWORD_REQUIRED not in connection.output:
        pytest.fail(
            f"sudo did not fail on its password stage: {connection.describe()}",
            pytrace=False,
        )


@given(
    parsers.re(
        r'the administrator serves "(?P<answer>[^"]+)" on port "(?P<port>\d+)" '
        r'of "(?P<host>[\w.-]+)"'
    )
)
def administrator_serves(answer: str, port: str, host: str, fleet: Fleet) -> None:
    """A page answers on a port of a machine, for the channels to reach.

    It stands for the service a user reaches behind the bastion: the
    channel forwards any port the user names, and what listens there is
    their business. It is started once, so the scenarios that open a
    channel to it share it rather than starting a second one.

    """
    machine = fleet.machine(host)
    unit = f"ob-lab-forwarding-{port}"
    # The address the bastion will dial, so that a service bound to the
    # loopback alone does not pass for one the channel can reach.
    ready = (
        "/usr/bin/python3 -c 'import socket, sys; "
        "s = socket.socket(socket.AF_INET); s.settimeout(1); "
        f'sys.exit(0 if s.connect_ex(("{machine.ip}", {port})) == 0 else 1)\''
    )
    script = "\n".join(
        [
            f"mkdir -p {SERVICE_ROOT}",
            f"printf '%s\\n' {shlex.quote(answer)} > {SERVICE_ROOT}/index.html",
            f"systemctl is-active --quiet {unit} && exit 0",
            f"systemd-run --unit={unit} --collect /usr/bin/python3 -m http.server"
            f" {port} --bind 0.0.0.0 --directory {SERVICE_ROOT}",
            f"for _ in $(seq 1 30); do {ready} && exit 0; sleep 1; done",
            f"echo 'nothing answers on port {port} of {host}'; exit 1",
        ]
    )
    result = fleet.run_as_root(machine, script)
    if not result.succeeded:
        pytest.fail(
            f"Could not serve {answer!r} on port {port} of {host}: "
            f"{result.describe()}",
            pytrace=False,
        )


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? forwards port "(?P<port>\d+)" of '
        r'"(?P<target>[\w.-]+)" through "(?P<bastion>[\w.-]+)"'
    ),
    target_fixture="connection",
)
def user_forwards(
    name: str,
    port: str,
    target: str,
    bastion: str,
    fleet: Fleet,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> ChannelResult:
    """Reach a port of a machine through a channel the bastion opens.

    The channel is the one ``ssh -L`` forwards a local port through, and
    the one ProxyJump rides: the bastion dials the port and relays, so it
    reaches whatever the bastion can reach. One request is written
    through it, and what comes back is the answer of the service it lands
    on.

    The target is dialled by the address the lab gives the machine: it is
    the bastion that resolves a name in the channel, and what the hosts
    of the fleet answer for each other is not what the scenario is about.

    """
    address = fleet.machine(target).ip
    return user_factory(name).forward(
        bastion, address, int(port), user_ssh_config, "GET / HTTP/1.0\r\n\r\n"
    )


@then(parsers.re(r'the forwarded port answers "(?P<answer>[^"]+)"'))
def forwarded_port_answers(answer: str, connection: ChannelResult) -> None:
    """The service behind the bastion answered through the channel."""
    if answer not in connection.stdout:
        pytest.fail(
            f"The forwarded port did not answer {answer!r}: {connection.describe()}",
            pytrace=False,
        )


@then(parsers.re(r'"(?P<bastion>[\w.-]+)" holds no recording of "(?P<name>[^"]+)"'))
def bastion_holds_no_recording(bastion: str, name: str, fleet: Fleet) -> None:
    """The bastion kept nothing of what the channel carried.

    Recording is what the bastion does with a session, and a forwarded
    channel is not one: what it relayed leaves no trace on the machine
    the user is authenticated to.

    """
    machine = fleet.machine(bastion)
    result = fleet.run_as_root(
        machine, f"ls -A {SESSIONS}/{name} 2>/dev/null; echo END"
    )
    kept = [
        line for line in result.stdout.splitlines() if line.strip() and line != "END"
    ]
    if not result.succeeded or kept:
        pytest.fail(
            f"{bastion} kept something of {name}: {kept or result.describe()}",
            pytrace=False,
        )


@when(
    parsers.re(
        r'user "?(?P<name>[\w.-]+)"? tries to connect to "(?P<backend>[^"]+)" '
        r'through "(?P<bastion>[\w.-]+)" with SSH ProxyJump'
    ),
    target_fixture="connection",
)
def user_connects_with_proxy_jump(
    name: str,
    backend: str,
    bastion: str,
    user_factory: Callable[[str], User],
    user_ssh_config: Path,
) -> SshResult:
    """Reach a backend by ProxyJump, the way a user would without ob-ssh.

    The bastion relays the connection and nothing more: the certificate
    the client presents to the backend is the user's own, and a backend
    accepts a certificate only when a bastion vouched for it.

    """
    return user_factory(name).proxy_jump(bastion, backend, user_ssh_config)


@then(
    parsers.re(r'"(?P<backend>[\w.-]+)" refused the certificate of "(?P<name>[^"]+)"')
)
def backend_refused_the_certificate(
    backend: str, name: str, connection: SshResult, fleet: Fleet
) -> None:
    """The backend turned the certificate down, the bastion having accepted it.

    The hop reaches the backend and offers it the very certificate the
    bastion took. A backend accepts a certificate only when a bastion
    vouched for it, so the refusal names the machine the hop was for — and
    not the transport, nor the host key of a machine on the way, which
    would leave the scenario passing on a hop that never got there.

    ssh names that machine as it reached it: the address when the
    connection went through a jump host, the name it was given when it did
    not.

    """
    refused = [
        f"{name}@{host}: Permission denied"
        for host in (backend, fleet.machine(backend).ip)
    ]
    if not any(marker in connection.output for marker in refused):
        pytest.fail(
            f"{backend} did not refuse the certificate of {name}: "
            f"{connection.describe()}",
            pytrace=False,
        )


@given(parsers.re(r'the administrator closes TCP forwarding on "(?P<host>[\w.-]+)"'))
def administrator_closes_tcp_forwarding(host: str, fleet: Fleet) -> None:
    """Stop a machine from opening forwarded channels.

    sshd permits TCP forwarding by default and the deployment leaves it
    there, so this is the drop-in the study's remediation is about. It is
    left in place: the scenario asking about the refusal is the last of
    its feature, and the machines are restored before the next one.

    """
    machine = fleet.machine(host)
    drop_in = "/etc/ssh/sshd_config.d/99-ob-lab-no-forwarding.conf"
    result = fleet.run_as_root(
        machine,
        f"printf '%s\\n' 'AllowTcpForwarding no' > {drop_in}\nsystemctl restart sshd",
    )
    if not result.succeeded:
        pytest.fail(
            f"Could not close TCP forwarding on {host}: {result.describe()}",
            pytrace=False,
        )


@then("the refusal comes from the forwarding policy")
def refusal_comes_from_the_forwarding_policy(connection: ChannelResult) -> None:
    """sshd turned the channel down instead of a machine behind it.

    What sshd answers a client asking for a channel it does not forward is
    "administratively prohibited": the bastion never dialled the target,
    so the refusal is the policy that was just applied to it and not the
    fleet the channel was meant to reach.

    """
    if FORWARDING_REFUSED not in connection.output:
        pytest.fail(
            f"sshd did not refuse the channel from its forwarding policy: "
            f"{connection.describe()}",
            pytrace=False,
        )


@then(parsers.parse("the result is {expected}"))
def result_is(connection: Connection, expected: str) -> None:
    if expected == "success":
        assert connection.succeeded, connection.describe()
    else:
        assert connection.denied, connection.describe()

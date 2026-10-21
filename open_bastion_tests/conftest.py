"""Fixtures of the open-bastion functional tests.

The tests take the lab over: they create the fleet, snapshot it, and delete
it at the end. Bringing a fleet up and deploying open-bastion on it takes
minutes, so a module, one feature, owns a fleet in the state its first step
describes: the snapshot is restored once for the module and the playbook is
built and played once. What the scenarios of a module then do to the
machines, signing a key and opening a session, is cheap and does not decide
what the next scenario sees.

What a failing scenario produced is left in a working directory whose path is
printed in the header of the run, and which is kept when the run fails. The
fleet and the portal are kept as well, and the end of the run tells how to
free them: the state a failure came from is what one wants to look at.

"""

from collections.abc import Callable, Iterator
from pathlib import Path

import logging
import pytest
import re
import shutil
import tempfile
import urllib.error
import urllib.request

from open_bastion_tests.support import command
from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import ADMIN_USER, Llng, Session
from open_bastion_tests.support.playbook import Administrator, apt_repository_url
from open_bastion_tests.support.ssh import User

MAINTAINER_KEY_NAME = "id_ob_tests_maintainer"

PACKAGES_INDEX = "Packages"
PACKAGES_PACKAGE = "Package: open-bastion"
PACKAGES_TIMEOUT = 10.0

LOGGER = logging.getLogger(__name__)

WORK_DIR_KEY = pytest.StashKey[Path]()
KEPT_LAB_KEY = pytest.StashKey[list[str]]()


def _named(request: pytest.FixtureRequest, fixture: str, attribute: str) -> Path | str:
    """Value a test module gave to a fixture, or why it did not."""
    value = getattr(request, "param", None)
    if value is None:
        pytest.fail(
            f"{request.module.__name__} does not name its {fixture}: add\n"
            f'  pytest.mark.parametrize("{fixture}", [{attribute}], indirect=True)',
            pytrace=False,
        )
    return value


def _slug(name: str) -> str:
    return re.sub(r"[^\w.]+", "-", name).strip("-")


def _keep_lab(request: pytest.FixtureRequest, cleanup: str) -> None:
    """Leave what the run created in place, and record how to free it."""
    LOGGER.info("Leaving the lab up: free it with `%s`", cleanup)
    request.config.stash.setdefault(KEPT_LAB_KEY, []).append(cleanup)


def pytest_configure(config: pytest.Config) -> None:
    config.stash[WORK_DIR_KEY] = Path(tempfile.mkdtemp(prefix="ob-lab-tests-"))


def pytest_report_header(config: pytest.Config) -> str:
    return f"artifacts: {config.stash[WORK_DIR_KEY]}"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    work_dir = session.config.stash[WORK_DIR_KEY]
    if exitstatus == pytest.ExitCode.OK:
        shutil.rmtree(work_dir, ignore_errors=True)
    else:
        print(f"\nArtifacts of the run kept in {work_dir}")
        kept = session.config.stash.get(KEPT_LAB_KEY, [])
        if kept:
            print("The lab was left running; free it with:")
            for cleanup in kept:
                print(f"  {cleanup}")


@pytest.fixture(scope="session")
def work_dir(request: pytest.FixtureRequest) -> Path:
    return request.config.stash[WORK_DIR_KEY]


@pytest.fixture(scope="module")
def module_dir(request: pytest.FixtureRequest, work_dir: Path) -> Path:
    """Where everything built for a feature is written."""
    path = work_dir / _slug(request.node.name.removesuffix(".py"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def scenario_dir(request: pytest.FixtureRequest, module_dir: Path) -> Path:
    """Where everything a single scenario produces is written."""
    path = module_dir / _slug(request.node.name)
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def packages_server() -> None:
    """The repository the fleet installs open-bastion from answers.

    It is the lab's, not the tests': a session that starts without it
    spends minutes creating the fleet and dies in the middle of the play,
    with ansible reporting the output of a failing apt task. Asking for
    the index at the address the machines are given fails in a second
    instead, and says what is missing. See "Build dev packages and serve
    locally" in README.md.

    """
    url = apt_repository_url()
    index = f"{url}/{PACKAGES_INDEX}"
    try:
        with urllib.request.urlopen(index, timeout=PACKAGES_TIMEOUT) as response:
            body = response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        pytest.fail(
            f"The server at {url} answered {error.code} for {index}: it "
            f'serves no APT index. Regenerate it, see "Build dev packages '
            f'and serve locally" in README.md',
            pytrace=False,
        )
    except (urllib.error.URLError, OSError) as error:
        pytest.fail(
            f"No package server at {url} ({error}): the fleet installs "
            f"open-bastion from it and the tests do not start it. See "
            f'"Build dev packages and serve locally" in README.md',
            pytrace=False,
        )
    if PACKAGES_PACKAGE not in body:
        pytest.fail(
            f"The server at {url} serves an index without "
            f"{PACKAGES_PACKAGE!r}: the fleet would have nothing to install. "
            f'Republish the packages, see "Build dev packages and serve '
            f'locally" in README.md',
            pytrace=False,
        )
    LOGGER.info("The package server of the lab answers at %s", url)


@pytest.fixture(scope="session")
def maintainer_key(work_dir: Path) -> Path:
    """The key pair the tests reach the maintainer account of the guests with.

    The tests make their own: which keys the machine that runs them happens
    to have in its home directory is not their business.

    """
    key = work_dir / MAINTAINER_KEY_NAME
    result = command.run(
        [
            command.which("ssh-keygen"),
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "ob-lab-tests",
            "-f",
            str(key),
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate {key}: {result.stderr}")
    LOGGER.debug("Generated %s", key)
    return key


@pytest.fixture(scope="session")
def fleet(
    request: pytest.FixtureRequest, maintainer_key: Path, packages_server: None
) -> Iterator[Fleet]:
    """The machines the scenarios run against, deleted at the end.

    The module that asks for it names the fleet, by indirect
    parametrization, and the Background of its feature tells the same
    name. A run that failed leaves the machines up for inspection. The
    package server is asked for first: it is what the deployment needs and
    the only prerequisite that costs nothing to check.

    """
    name = _named(request, "fleet", "FLEET")
    fleet = Fleet(str(name), maintainer_key)
    existing = sorted(machine.name for machine in fleet.existing())
    if existing:
        pytest.fail(
            f"Machines {', '.join(existing)} already exist: free the lab with "
            f"`ob-lab -f {fleet.name} delete` before running the tests",
            pytrace=False,
        )

    try:
        fleet.start()
        fleet.wait_for_cloud_init()
        fleet.snapshot()
        yield fleet
    finally:
        if request.session.testsfailed:
            _keep_lab(request, f"ob-lab -f {fleet.name} delete")
        else:
            fleet.delete()


@pytest.fixture(scope="module")
def fresh_fleet(fleet: Fleet) -> Fleet:
    """The fleet as it was when the session snapshotted it. All
    machines started."""
    fleet.restore()
    return fleet


@pytest.fixture(scope="session")
def llng_runtime(request: pytest.FixtureRequest, work_dir: Path) -> Iterator[Llng]:
    """The portal, running in its own compose project for the whole session.

    A run that failed leaves it up for inspection.

    """
    llng = Llng(data("llng/docker-compose.yml"))
    running = llng.running()
    if running:
        pytest.fail(
            f"The LLNG compose project is already running ({', '.join(running)}): "
            f"clean the environment up with\n"
            f"  docker compose -f {llng.compose_file} down -v",
            pytrace=False,
        )

    llng.up()
    yield llng
    llng.save_logs(work_dir / "llng.log")
    if request.session.testsfailed:
        _keep_lab(request, f"docker compose -f {llng.compose_file} down -v")
    else:
        llng.down()


@pytest.fixture(scope="module")
def llng(request: pytest.FixtureRequest, llng_runtime: Llng) -> Llng:
    """The portal configured with the configuration the module names.

    The Background of the feature tells the same name.

    """
    llng_runtime.restore(Path(_named(request, "llng", "LLNG_CONFIG")))
    return llng_runtime


@pytest.fixture(scope="module")
def administrator(module_dir: Path, maintainer_key: Path) -> Administrator:
    return Administrator(module_dir, maintainer_key)


@pytest.fixture(scope="module")
def playbook(administrator: Administrator) -> Path:
    """The playbook of the default configuration, built once for the module."""
    return administrator.generate_playbook()


@pytest.fixture(scope="module")
def portal_sessions(llng: Llng) -> Callable[[str], Session | None]:
    """The session of a user, opened once for the feature.

    A user logs in once: the portal answers a second login, while the
    session of that user is open, with its login form rather than with a
    session, and the scenarios of a feature share the machines anyway.

    """
    return llng.session


@pytest.fixture(scope="module")
def portal_session(llng: Llng) -> Session:
    """The session the administrator approves enrolments with."""
    session = llng.session(ADMIN_USER)
    assert session is not None
    if session is None:
        pytest.fail(f"{ADMIN_USER} cannot open a session on the portal")
    return session


@pytest.fixture(scope="module")
def deployed_fleet(
    administrator: Administrator,
    playbook: Path,
    fresh_fleet: Fleet,
    portal_session: Session,
) -> Fleet:
    """The fleet open-bastion is installed and enrolled on."""
    administrator.play_playbook(fresh_fleet, portal_session)
    return fresh_fleet


@pytest.fixture(scope="module")
def local_user_home(module_dir: Path) -> Path:
    """Where the keys of the accounts the portal does not know live.

    A key copied to a machine before it is configured has to outlive the
    scenario that copied it: the other scenarios of the feature use it.

    """
    home = module_dir / "ssh"
    home.mkdir(parents=True, exist_ok=True)
    return home


@pytest.fixture(scope="module")
def copied_public_keys(
    fresh_fleet: Fleet, local_user_home: Path
) -> Callable[[str, str], User]:
    """Copy the key of a local account to a machine, once per feature.

    The copy happens while the machines still accept the password of their
    accounts, so it belongs to the state the feature starts from, and every
    scenario of the feature shares it.

    """
    copied: dict[tuple[str, str], User] = {}

    def copy(account: str, host: str) -> User:
        key = (account, host)
        if key not in copied:
            user = User(name=account, home=local_user_home)
            user.ensure_key()
            fresh_fleet.copy_public_key(fresh_fleet.machine(host), account, user.key)
            copied[key] = user
        return copied[key]

    return copy


@pytest.fixture
def user_factory(scenario_dir: Path) -> Callable[[str], User]:
    """Users whose key and certificate land in the scenario directory."""
    home = scenario_dir / "ssh"
    home.mkdir(parents=True, exist_ok=True)

    def factory(name: str) -> User:
        return User(name=name, home=home)

    return factory


@pytest.fixture
def user_ssh_config(scenario_dir: Path, local_user_home: Path) -> Path:
    """The ssh configuration of the scenario.

    It reads the keys of the scenario first, then those the feature copied
    to a machine before it was configured. Both are pointed at by an
    absolute path: ssh expands ``~`` from the passwd database, not from
    ``HOME``, so a configuration file cannot be told to look elsewhere.

    """
    scenario_keys = scenario_dir / "ssh" / ".ssh"
    copied_keys = local_user_home / ".ssh"
    path = scenario_dir / "ssh_config"
    path.write_text(
        data("ssh_config")
        .read_text()
        .replace(
            'IdentityFile "~/.ssh/id_%r"',
            f'IdentityFile "{scenario_keys}/id_%r"\n    '
            f'IdentityFile "{copied_keys}/id_%r"',
        )
    )
    return path

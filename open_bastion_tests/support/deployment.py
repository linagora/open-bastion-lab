"""What an administrator does to a fleet: build an artefact, or play it.

ob-builder writes two kinds of artefact for the same deployment, one per
target role: an Ansible tree a control node plays, and a self-extracting
installer each target runs itself. This module holds what both need — the
key of the tests folded into the configuration, the repository the fleet
installs from — and what running the Ansible one did.

What a feature deploys, and with which configuration, is what its steps
name; nothing here decides it.

"""

from dataclasses import dataclass
from pathlib import Path

import json
import logging
import re

from open_bastion_lab.model import Role

from open_bastion_tests.support import command, public_key
from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import PORTAL_URL, Session
from open_bastion_tests.support.ssh import User

LOGGER = logging.getLogger(__name__)

KEY_PATTERN = re.compile(r"^(?P<indent>[ \t]*)public_key_file:.*$", re.MULTILINE)
INVENTORY_KEY_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)ansible_ssh_private_key_file:.*$", re.MULTILINE
)
APT_SOURCES_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)ob_apt_sources_list_line:[ \t]*(?P<line>\S.*)$", re.MULTILINE
)
APT_URL_PATTERN = re.compile(r"https?://[^\s\"]+")
TARGET_ROLE_PATTERN = re.compile(r"^target_role:.*$", re.MULTILINE)
ALLOWED_BASTIONS_PATTERN = re.compile(r"^allowed_bastions:.*$", re.MULTILINE)

PLAYBOOK = "site.yml"
LOG = "ansible-playbook.log"
BUILD_LOG = "ob-builder.log"
INSTALLERS = "shell"


# Every inventory the tests own points the fleet at the same repository, the
# lab's own; a check that runs before a feature named a fleet reads that one.
LAB_INVENTORY = data("inventory-for-two-backends.yml")


def inventory_for(fleet: Fleet) -> Path:
    """The inventory the tests own for a fleet, named after it."""
    return data(f"inventory-for-{fleet.name}.yml")


def llng_configuration(name: str) -> Path:
    """The portal configuration the tests own, named as a feature names it."""
    return data(f"llng/with-two-oidc-rp/{name}.json")


def apt_repository_url(inventory: Path = LAB_INVENTORY) -> str:
    """Base URL of the repository an inventory gives the fleet.

    Read from the inventory the machines are given, so a check of that
    repository looks at the address they install from.

    """
    sources = APT_SOURCES_PATTERN.search(inventory.read_text())
    if sources is None:
        raise RuntimeError(f"No ob_apt_sources_list_line in {inventory}")
    url = APT_URL_PATTERN.search(sources.group("line"))
    if url is None:
        raise RuntimeError(
            f"No URL in {sources.group('line').strip()!r}, read from {inventory}"
        )
    return url.group(0).rstrip("/")


@dataclass
class Play:
    """What a play did, as its recap reports it."""

    log: Path
    returncode: int

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    def text(self) -> str:
        return self.log.read_text(errors="replace")

    def recap(self, host: str) -> dict[str, int]:
        """Counters the play left for a host."""
        text = self.text()
        found = re.search(rf"^{re.escape(host)}\s*:\s*(?P<counters>.*)$", text, re.M)
        if found is None:
            return {}
        return {
            key: int(value)
            for key, value in re.findall(r"(\w+)=(\d+)", found["counters"])
        }

    def describe(self) -> str:
        return f"ansible-playbook returned {self.returncode}, see {self.log}"


class Administrator:
    """An administrator deploying open-bastion on a fleet.

    It builds with the configuration a step names, one of the files the
    tests own, and with the key they made for the maintainer account: no
    other key is involved, in that configuration or in the inventory.

    The artefacts it built and the plays it ran are kept: the Background of
    a feature runs again before each of its scenarios, and building or
    deploying sixteen times is not what it describes.

    """

    work_dir: Path
    key: Path
    playbooks: dict[str, Path]
    plays: dict[tuple[str, str], Play]

    def __init__(self, work_dir: Path, key: Path):
        self.work_dir = work_dir
        self.key = key
        self.playbooks = {}
        self.plays = {}

    def generate_playbook(self, configuration: str) -> Path:
        """Generate the playbook of a configuration, once.

        ob-builder reaches the portal while building: it reads the SSO
        metadata, the SSH CA key and the revocation list from it.

        """
        playbook = self.playbooks.get(configuration)
        if playbook is not None:
            return playbook

        source = data(f"{configuration}.yml")
        config_file = self.work_dir / source.name
        config_file.write_text(self._config(source))

        output = self.work_dir / "ansible"
        args = [
            command.which("ob-builder"),
            "--config",
            str(config_file),
            "--output-ansible",
            str(output),
        ]
        log = self.work_dir / BUILD_LOG
        result = command.run(args, log=log)
        if result.returncode != 0:
            raise RuntimeError(f"ob-builder failed, see {log}")

        playbook = output / PLAYBOOK
        if not playbook.is_file():
            raise RuntimeError(f"No playbook generated at {playbook}")
        LOGGER.info("Generated %s", playbook)
        self.playbooks[configuration] = playbook
        return playbook

    def generate_installer(
        self,
        configuration: str,
        role: Role,
        *,
        allowed_bastions: str | None = None,
    ) -> Path:
        """Write the self-extracting installer of one role.

        ob-builder reaches the portal while building, as it does for a
        playbook. The role is part of the build: one installer per target,
        and a backend installer also bakes the bastions it accepts, ids that
        only exist once the bastion is enrolled.

        """
        source = data(f"{configuration}.yml")
        text, count = TARGET_ROLE_PATTERN.subn(
            f'target_role: "{role}"', self._config(source)
        )
        if count == 0:
            raise RuntimeError(f"No target_role to set in {source}")
        # The configuration leaves the ids to null, which asks the Ansible
        # role to collect them from the bastions; a shell build has no play
        # to do that and refuses the value, so it says "any bastion" instead.
        identifier = allowed_bastions or ""
        text, count = ALLOWED_BASTIONS_PATTERN.subn(
            f'allowed_bastions: "{identifier}"', text
        )
        if count == 0:
            raise RuntimeError(f"No allowed_bastions to set in {source}")
        config_file = self.work_dir / f"{source.stem}-{role}.yml"
        config_file.write_text(text)

        output = self.work_dir / INSTALLERS
        args = [
            command.which("ob-builder"),
            "--config",
            str(config_file),
            "--output-shell",
            str(output),
        ]
        log = self.work_dir / f"{BUILD_LOG}-{role}"
        result = command.run(args, log=log)
        if result.returncode != 0:
            raise RuntimeError(f"ob-builder failed, see {log}")

        installer = next(output.glob(f"bootstrap-*-{role}.sh"), None)
        if installer is None:
            raise RuntimeError(f"No installer for the {role} role in {output}")
        LOGGER.info("Generated %s", installer)
        return installer

    def play_once(
        self, fleet: Fleet, session: Session, inventory: Path, *, limit: str | None
    ) -> Play:
        """Play the tree once for a fleet and a limit, then answer what it did."""
        key = (fleet.name, limit or "")
        play = self.plays.get(key)
        if play is None:
            play = self.play_playbook(fleet, session, inventory, limit=limit)
            self.plays[key] = play
        return play

    def play_playbook(
        self,
        fleet: Fleet,
        session: Session,
        inventory: Path,
        *,
        as_user: User | None = None,
        limit: str | None = None,
    ) -> Play:
        """Install open-bastion on the fleet and enrol it against the portal.

        Given a user, the play runs as that SSO user, connecting with its
        certificate and minting a token at each sudo prompt: once deployed
        under maximum security, that is the way to configure a host again.

        The caller reads the outcome: a play that fails is a scenario's
        subject as much as one that succeeds.

        """
        known_hosts = self.work_dir / "known_hosts"
        known_hosts.touch()
        common = (
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile={known_hosts}"
            " -o IdentitiesOnly=yes"
        )
        extra = {"ob_llng_cookie": session.cookie, "ansible_ssh_common_args": common}
        if as_user is not None:
            extra.update(
                {
                    "ansible_user": as_user.name,
                    "ansible_ssh_private_key_file": str(as_user.key),
                    "ansible_ssh_common_args": (
                        f"{common} -o CertificateFile={as_user.certificate}"
                    ),
                    "ansible_become_token_cmd": str(self._token_command(session)),
                    # Ignored by ob_sudo_sso, which mints the token per prompt;
                    # set so that ansible asks the become plugin for one.
                    "ansible_become_password": "ob-sso",
                }
            )
        args = [
            command.which("ansible-playbook"),
            "-i",
            str(self._inventory(inventory)),
            PLAYBOOK,
        ]
        if limit is not None:
            args += ["--limit", limit]
        args += ["-e", json.dumps(extra)]
        log = self.work_dir / (
            LOG if limit is None else f"ansible-playbook-{limit}.log"
        )
        result = command.run(
            args,
            cwd=self.work_dir / "ansible",
            env=command.environment(ANSIBLE_HOST_KEY_CHECKING="False"),
            log=log,
        )
        if result.returncode != 0:
            LOGGER.info("The play failed, see %s", log)
        return Play(log=log, returncode=result.returncode)

    def _token_command(self, session: Session) -> Path:
        """A command the controller runs at each sudo prompt to mint a token.

        The cookie is the session the run opened for that user: llng keeps
        one shared jar and this version ignores --cookie-jar and
        --force-renew, so asking it to log in would mint a token for whoever
        the jar last held.

        """
        script = self.work_dir / "token-cmd"
        script.write_text(
            "#!/bin/sh\n"
            "set -e\n"
            f"curl -fsS -X POST -b {session.cookie} {PORTAL_URL}/pam | "
            "python3 -c 'import json, sys; print(json.load(sys.stdin)[\"token\"])'\n"
        )
        script.chmod(0o755)
        return script

    def _config(self, source: Path) -> str:
        """The configuration to build with, holding the key of the tests.

        The test owned copy holds a path that is only valid next to the
        examples, so the key is written as an absolute path. The rest of the
        file is left untouched, comments included.

        """
        text, count = KEY_PATTERN.subn(
            rf"\g<indent>public_key_file: {public_key(self.key)}",
            source.read_text(),
        )
        if count == 0:
            raise RuntimeError(f"No public_key_file to set in {source}")
        return text

    def _inventory(self, inventory: Path) -> Path:
        """The inventory, with the key of the tests instead of the example one."""
        text, count = INVENTORY_KEY_PATTERN.subn(
            rf"\g<indent>ansible_ssh_private_key_file: {self.key}",
            inventory.read_text(),
        )
        if count == 0:
            raise RuntimeError(f"No ansible_ssh_private_key_file in {inventory}")

        path = self.work_dir / inventory.name
        path.write_text(text)
        return path

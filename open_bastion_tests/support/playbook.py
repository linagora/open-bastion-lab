"""What an administrator does to the fleet: build and play a playbook."""

from dataclasses import dataclass
from pathlib import Path

import json
import logging
import re

import yaml

from open_bastion_tests.support import command, public_key
from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import PORTAL_URL, Session
from open_bastion_tests.support.ssh import User

LOGGER = logging.getLogger(__name__)

INVENTORY_FILE = data("inventory.yml")
NEXT_INVENTORY_FILE = data("inventory-with-third-backend.yml")

KEY_PATTERN = re.compile(r"^(?P<indent>[ \t]*)public_key_file:.*$", re.MULTILINE)
INVENTORY_KEY_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)ansible_ssh_private_key_file:.*$", re.MULTILINE
)
APT_SOURCES_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)ob_apt_sources_list_line:[ \t]*(?P<line>\S.*)$", re.MULTILINE
)
APT_URL_PATTERN = re.compile(r"https?://[^\s\"]+")

PLAYBOOK = "site.yml"
LOG = "ansible-playbook.log"
BUILD_LOG = "ob-builder.log"


def inventory_hosts(source: Path = INVENTORY_FILE) -> list[str]:
    """Machines the play is asked to configure."""
    groups = yaml.safe_load(source.read_text())["all"]["children"]
    return [host for group in groups.values() for host in group.get("hosts", {})]


def apt_repository_url() -> str:
    """Base URL of the repository the fleet installs packages from.

    Read from the inventory the tests hand to ansible-playbook, so a check
    of that repository looks at the address the machines are given.

    """
    sources = APT_SOURCES_PATTERN.search(INVENTORY_FILE.read_text())
    if sources is None:
        raise RuntimeError(f"No ob_apt_sources_list_line in {INVENTORY_FILE}")
    url = APT_URL_PATTERN.search(sources.group("line"))
    if url is None:
        raise RuntimeError(
            f"No URL in {sources.group('line').strip()!r}, read from {INVENTORY_FILE}"
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

    def recap(self, host: str) -> dict[str, int]:
        """Counters the play left for a host."""
        text = self.log.read_text(errors="replace")
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
    """An administrator deploying open-bastion on the fleet.

    It builds with the configuration the module names, one of the files the
    tests own, and with the key they made for the maintainer account: no
    other key is involved, in that configuration or in the inventory.

    """

    work_dir: Path
    key: Path
    configuration: str

    def __init__(self, work_dir: Path, key: Path, configuration: str):
        self.work_dir = work_dir
        self.key = key
        self.configuration = configuration

    def generate_playbook(self) -> Path:
        """Generate the playbook of the configuration it was given.

        ob-builder reaches the portal while building: it reads the SSO
        metadata, the SSH CA key and the revocation list from it.

        """
        source = data(f"{self.configuration}.yml")
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
        return playbook

    def play_playbook(
        self,
        fleet: Fleet,
        session: Session,
        *,
        as_user: User | None = None,
        limit: str | None = None,
        source: Path = INVENTORY_FILE,
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
        # Extra variables are given as JSON: a "name=value" one is split on
        # spaces by ansible, which mangles the options below.
        common = f"-o StrictHostKeyChecking=no -o UserKnownHostsFile={known_hosts}"
        extra = {"ob_llng_cookie": session.cookie, "ansible_ssh_common_args": common}
        if as_user is not None:
            extra.update(
                {
                    "ansible_user": as_user.name,
                    "ansible_ssh_private_key_file": str(as_user.key),
                    "ansible_ssh_common_args": (
                        f"{common} -o IdentitiesOnly=yes"
                        f" -o CertificateFile={as_user.certificate}"
                    ),
                    "ansible_become_token_cmd": str(self._token_command(session)),
                }
            )
        args = [
            command.which("ansible-playbook"),
            "-i",
            str(self._inventory(source)),
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
        """A command the controller runs at each sudo prompt to mint a token."""
        script = self.work_dir / "token-cmd"
        script.write_text(
            "#!/bin/sh\n"
            f"curl -sS -X POST -b {session.cookie} {PORTAL_URL}/pam | "
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

    def _inventory(self, source: Path = INVENTORY_FILE) -> Path:
        """The inventory, with the key of the tests instead of the example one."""
        text, count = INVENTORY_KEY_PATTERN.subn(
            rf"\g<indent>ansible_ssh_private_key_file: {self.key}",
            source.read_text(),
        )
        if count == 0:
            raise RuntimeError(f"No ansible_ssh_private_key_file in {source}")

        path = self.work_dir / source.name
        path.write_text(text)
        return path

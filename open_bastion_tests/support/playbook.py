"""What an administrator does to the fleet: build and play a playbook."""

from pathlib import Path

import json
import logging
import re

from open_bastion_tests.support import command, public_key
from open_bastion_tests.support.fleet import Fleet, data
from open_bastion_tests.support.llng import Session

LOGGER = logging.getLogger(__name__)

CONFIG_FILE = data("ob-builder-max-security.yml")
INVENTORY_FILE = data("inventory.yml")

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


class Administrator:
    """An administrator deploying open-bastion on the fleet.

    The key it is given is the one the tests made for the maintainer
    account: no other key is involved, in the configuration handed to
    ob-builder or in the inventory.

    """

    work_dir: Path
    key: Path

    def __init__(self, work_dir: Path, key: Path):
        self.work_dir = work_dir
        self.key = key

    @property
    def configuration(self) -> str:
        """Name of the configuration the administrator builds with."""
        return CONFIG_FILE.stem

    def generate_playbook(self) -> Path:
        """Generate the playbook of the default configuration.

        ob-builder reaches the portal while building: it reads the SSO
        metadata, the SSH CA key and the revocation list from it.

        """
        config_file = self.work_dir / CONFIG_FILE.name
        config_file.write_text(self._config())

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

    def play_playbook(self, fleet: Fleet, session: Session) -> None:
        """Install open-bastion on the fleet and enrol it against the portal."""
        known_hosts = self.work_dir / "known_hosts"
        known_hosts.touch()
        # Extra variables are given as JSON: a "name=value" one is split on
        # spaces by ansible, which mangles the options below.
        extra = {
            "ob_llng_cookie": session.cookie,
            # The machines are recreated between runs, so their host keys are
            # not the ones of the last time: the play keeps its own file, and
            # never reads or writes the one of whoever runs the tests.
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no"
            f" -o UserKnownHostsFile={known_hosts}",
        }
        args = [
            command.which("ansible-playbook"),
            "-i",
            str(self._inventory()),
            PLAYBOOK,
            "-e",
            json.dumps(extra),
        ]
        log = self.work_dir / LOG
        result = command.run(
            args,
            cwd=self.work_dir / "ansible",
            env=command.environment(ANSIBLE_HOST_KEY_CHECKING="False"),
            log=log,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Playing the playbook failed, see {log}")

    def _config(self) -> str:
        """The default configuration, with the key of the tests.

        The test owned copy holds a path that is only valid next to the
        examples, so the key is written as an absolute path. The rest of the
        file is left untouched, comments included.

        """
        text, count = KEY_PATTERN.subn(
            rf"\g<indent>public_key_file: {public_key(self.key)}",
            CONFIG_FILE.read_text(),
        )
        if count == 0:
            raise RuntimeError(f"No public_key_file to set in {CONFIG_FILE}")
        return text

    def _inventory(self) -> Path:
        """The inventory, with the key of the tests instead of the example one."""
        text, count = INVENTORY_KEY_PATTERN.subn(
            rf"\g<indent>ansible_ssh_private_key_file: {self.key}",
            INVENTORY_FILE.read_text(),
        )
        if count == 0:
            raise RuntimeError(f"No ansible_ssh_private_key_file in {INVENTORY_FILE}")

        path = self.work_dir / INVENTORY_FILE.name
        path.write_text(text)
        return path

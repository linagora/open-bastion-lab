"""The LemonLDAP::NG the fleet authenticates against.

The portal is owned by the tests: they run their own compose project and
import the configuration each scenario asks for.

"""

from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

import json
import logging
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from open_bastion_tests.support import command

LOGGER = logging.getLogger(__name__)

PORTAL_URL = "http://auth.example.com"
CONTAINER = "llng"
CONTAINER_CONF_DIR = "/var/lib/lemonldap-ng/conf"
CONTAINER_SSH_DIR = "/var/lib/lemonldap-ng/ssh"

JWKS_TRIES = 30
PORTAL_TRIES = 60
LOGIN_RETRY_DELAY = 5.0
LOG_TAIL = 2000

# The configuration only lets the timelords approve device codes.
ADMIN_USER = "dwho"

TOKEN_PATTERN = re.compile(r'name="token" value="([^"]*)"')
MESSAGE_PATTERN = re.compile(r'class="alert[^"]*"[^>]*>(.*?)</div>', re.DOTALL)
TAG_PATTERN = re.compile(r"<[^>]+>")
CONF_NUMBER_PATTERN = re.compile(r"lmConf-(\d+)\.json")


def _message(body: str) -> str:
    """What the portal told the client, when it said something."""
    messages = [
        " ".join(TAG_PATTERN.sub(" ", found.group(1)).split())
        for found in MESSAGE_PATTERN.finditer(body)
    ]
    messages = [message for message in messages if message]
    return " | ".join(messages)[:300] if messages else "no message"


class LlngError(RuntimeError):
    """Raised when the portal does not answer as expected."""


@dataclass
class Session:
    """A session opened on the portal."""

    user: str
    cookie: str
    opener: urllib.request.OpenerDirector

    def post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(request, timeout=30) as response:
            body = response.read().decode()
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise LlngError(f"{url} answered {body[:200]!r}") from e


@dataclass
class Llng:
    compose_file: Path
    portal_url: str = PORTAL_URL
    config_file: Path | None = None
    config_number: int | None = None
    sessions: dict[str, Session | None] = field(default_factory=dict)

    def session(self, user: str) -> Session | None:
        """The session of a user, opened at most once.

        The portal answers a second login, while the session of that user
        is open, with its login form rather than with a session, and its
        session store locks nothing, so two logins in a row can also race.
        A user logs in once: the scenarios share what is opened here.

        """
        if user not in self.sessions:
            LOGGER.info("Opening the session of %s", user)
            session = self.login(user)
            if session is None:
                # The portal answers a login it does not follow with its form
                # and logs nothing, which happens when several logins come in
                # a row. Waiting a little and asking again is what a person
                # would do, and keeps the suite off LLNG's pacing.
                LOGGER.info("The portal refused the login of %s, asking again", user)
                time.sleep(LOGIN_RETRY_DELAY)
                session = self.login(user)
            self.sessions[user] = session
        else:
            LOGGER.info("Reusing the session of %s", user)
        return self.sessions[user]

    @property
    def configuration(self) -> str:
        """Name of the configuration the portal imported.

        The file it was read from is named after what it configures, and
        the scenarios name it the same way, without the extension.

        """
        if self.config_file is None:
            raise LlngError("No configuration was imported")
        return self.config_file.stem

    def ensure_configuration(self) -> None:
        """Import the configuration of the feature again when it drifted.

        A scenario may change the last configuration of the portal, and a
        feature does not decide the order its scenarios run in: importing
        the file again gives the next scenario the portal the feature
        starts from, whatever ran before it.

        """
        if self.config_file is None:
            raise LlngError("No configuration was imported")
        if self.latest_config_number() == self.config_number:
            return
        LOGGER.info(
            "The portal runs another configuration, restoring %s", self.config_file
        )
        self.restore(self.config_file)

    def running(self) -> list[str]:
        """Identifiers of the containers of the compose project."""
        result = self._compose("ps", "-q")
        return [line for line in result.stdout.split() if line]

    def up(self) -> None:
        self._compose("up", "-d", "--wait")
        # The SSH CA plugin rewrites the revocation list on every signature.
        self._exec(
            "install", "-d", "-o", "www-data", "-g", "www-data", CONTAINER_SSH_DIR
        )

    def down(self) -> None:
        self._compose("down", "-v")

    def reload(self) -> None:
        """Have every worker serve the configuration last imported.

        Each worker polls the configuration cache on a timer of its own, and
        they reload one after another: a change can take a minute to reach
        them all, which is longer than a scenario waits before asking the
        fleet to connect. Starting the portal again has them all load the
        current configuration.

        """
        self._compose("restart", CONTAINER)
        self._wait_for_portal()

    def save_logs(self, path: Path) -> None:
        """Write what the portal logged where a failing test can be read."""
        result = command.run(
            [
                "docker",
                "compose",
                "-f",
                str(self.compose_file),
                "logs",
                "--no-color",
                "--tail",
                str(LOG_TAIL),
            ]
        )
        path.write_text(result.stdout + result.stderr)

    def restore(self, config_file: Path) -> None:
        """Import a configuration, the portal is left running on it."""
        config = json.loads(config_file.read_text())
        config["cfgNum"] = self._next_config_number()
        LOGGER.info("Restoring %s as configuration %s", config_file, config["cfgNum"])

        self._exec(
            "lemonldap-ng-cli", "-yes", "1", "restore", "-", stdin=json.dumps(config)
        )
        self._exec("lemonldap-ng-cli", "update-cache")
        self.config_file = config_file
        self.config_number = config["cfgNum"]
        self.reload()
        self._wait_for_jwks()

    def _wait_for_jwks(self) -> None:
        """Wait for the portal to publish its signing keys.

        Just after an import the first answers carry a modulus and nothing
        else, which ob-builder rightly refuses to build artefacts from.

        """
        url = f"{self.portal_url}/oauth2/jwks"
        for _ in range(JWKS_TRIES):
            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    keys = json.loads(response.read().decode()).get("keys", [])
            except (urllib.error.URLError, json.JSONDecodeError) as e:
                LOGGER.debug("%s is not ready: %s", url, e)
            else:
                if keys and all("kty" in key for key in keys):
                    return
            time.sleep(1)
        raise LlngError(f"{url} never served a complete JWKS")

    def _wait_for_portal(self) -> None:
        """Wait for the portal to answer again after a restart."""
        for _ in range(PORTAL_TRIES):
            try:
                with urllib.request.urlopen(self.portal_url, timeout=5) as response:
                    if response.status == 200:
                        return
            except urllib.error.URLError as e:
                LOGGER.debug("%s is not ready: %s", self.portal_url, e)
            time.sleep(1)
        raise LlngError(f"{self.portal_url} never answered after a restart")

    def login(self, user: str) -> Session | None:
        """Open a session on the portal, or return None when the user has none.

        The demo backend authenticates any password equal to the login but
        only knows a few accounts: a user it does not know, which is how a
        user without SSO access behaves, ends up with no session.

        """
        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        with opener.open(f"{self.portal_url}/", timeout=30) as response:
            form = response.read().decode()
        token = TOKEN_PATTERN.search(form)
        if token is None or not token.group(1):
            raise LlngError(
                f"The portal of {self.portal_url} offered no login form to "
                f"{user}: {_message(form)}"
            )

        payload = urllib.parse.urlencode(
            {
                "user": user,
                "password": user,
                "token": token.group(1),
                "url": "",
                "skin": "bootstrap5",
            }
        ).encode()
        try:
            with opener.open(
                urllib.request.Request(f"{self.portal_url}/", data=payload), timeout=30
            ) as response:
                answer = response.read().decode()
                landed = response.url
        except urllib.error.HTTPError as e:
            raise LlngError(f"Login of {user} failed with {e.code}") from e

        cookie = self._cookie(jar)
        if cookie is None:
            LOGGER.info(
                "User %s got no session, the portal answered from %s: %s",
                user,
                landed,
                _message(answer),
            )
            return None
        return Session(user=user, cookie=cookie, opener=opener)

    def pam_ssh_rules(self) -> dict[str, str]:
        """SSH access rules of the portal, per server group."""
        result = self._exec("lemonldap-ng-cli", "-json", "get", "pamAccessSshRules")
        start = result.stdout.find("{")
        if start < 0:
            raise LlngError(f"No rules in {result.stdout!r}{result.stderr!r}")
        try:
            rules = json.loads(result.stdout[start:])
        except json.JSONDecodeError as e:
            raise LlngError(f"Unreadable rules: {result.stdout!r}") from e
        if not isinstance(rules, dict):
            raise LlngError(f"Unexpected rules: {rules!r}")
        return {str(group): str(rule) for group, rule in rules.items()}

    def set_pam_ssh_rules(self, rules: dict[str, str]) -> None:
        """Give the portal new SSH rules."""
        self._set_pam_rules("pamAccessSshRules", rules)

    def set_pam_sudo_rules(self, rules: dict[str, str]) -> None:
        """Give the portal new sudo rules."""
        self._set_pam_rules("pamAccessSudoRules", rules)

    def _set_pam_rules(self, key: str, rules: dict[str, str]) -> None:
        """Set a rule set of the portal, one value per server group."""
        for group, rule in rules.items():
            LOGGER.info("%s.%s becomes %r", key, group, rule)
            self._exec("lemonldap-ng-cli", "-yes", "1", "addKey", key, group, rule)
        self._exec("lemonldap-ng-cli", "update-cache")

    def pam_token(self, session: Session) -> str:
        """Ask the portal for a one-time token, in place of a password.

        The machines authenticate sudo through the portal: the user gives
        the token the portal handed to a signed-in session, and the PAM
        stack has it verified, once.

        """
        answer = session.post(f"{self.portal_url}/pam", {})
        token = answer.get("token")
        if not isinstance(token, str):
            raise LlngError(f"The portal gave no token to {session.user}: {answer}")
        return token

    def sign(self, session: Session, public_key: str, label: str, log: Path) -> str:
        """Ask the portal to sign a public key and return the certificate."""
        answer = session.post(
            f"{self.portal_url}/ssh/sign", {"public_key": public_key, "label": label}
        )
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps(answer, indent=2) + "\n")

        certificate = answer.get("certificate")
        if not isinstance(certificate, str):
            raise LlngError(f"Portal refused to sign for {session.user}: {answer}")
        return certificate

    def _cookie(self, jar: CookieJar) -> str | None:
        for cookie in jar:
            if cookie.name == "lemonldap":
                return f"{cookie.name}={cookie.value}"
        return None

    def latest_config_number(self) -> int:
        """Number of the last configuration the portal has."""
        result = self._exec("lemonldap-ng-cli", "-json", "info")
        start = result.stdout.find("{")
        if start < 0:
            raise LlngError(f"No configuration number in {result.stdout!r}")
        try:
            answer = json.loads(result.stdout[start:])
        except json.JSONDecodeError as e:
            raise LlngError(f"Unreadable configuration info: {result.stdout!r}") from e
        return int(answer["num"])

    def _next_config_number(self) -> int:
        result = self._exec("ls", CONTAINER_CONF_DIR)
        numbers = [int(match) for match in CONF_NUMBER_PATTERN.findall(result.stdout)]
        return max(numbers, default=0) + 1

    def _exec(
        self, *args: str, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self._compose("exec", "-T", CONTAINER, *args, stdin=stdin)

    def _compose(
        self, *args: str, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        result = command.run(
            ["docker", "compose", "-f", str(self.compose_file), *args], stdin=stdin
        )
        if result.returncode != 0:
            raise LlngError(
                f"docker compose {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
            )
        return result

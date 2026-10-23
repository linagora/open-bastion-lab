"""A user of the fleet and the SSH connection it may or may not get."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import logging
import subprocess

from open_bastion_lab.machine import Machine

from open_bastion_tests.support import command

LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
AUTHENTICATION_REFUSED = "Permission denied"
CONNECTION_CLOSED = "Connection closed by"
CERTIFICATE_REFUSED = "refused to issue a certificate"

# Failures of the attempt itself, which decide nothing about the fleet.
UNREACHABLE = (
    "Connection refused",
    "No route to host",
    "Connection timed out",
    "Could not resolve hostname",
    "command not found",
)


def _unreachable(output: str) -> bool:
    """True when an attempt failed before the machine could answer."""
    return any(marker in output for marker in UNREACHABLE)


class Connection(Protocol):
    """What a scenario asks of a connection: it works, or the fleet said no."""

    @property
    def succeeded(self) -> bool: ...

    @property
    def denied(self) -> bool: ...

    def describe(self) -> str: ...


@dataclass
class SshResult:
    """What a connection attempt did."""

    user: str
    host: str
    returncode: int
    stdout: str
    stderr: str
    signed: bool
    log: Path

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    @property
    def denied(self) -> bool:
        """True when the machine refused to open a session.

        A key it does not trust is answered with "Permission denied", a
        user its PAM stack refuses with a closed connection. A machine that
        cannot be reached answers neither, and does not count as a refusal.

        """
        return not self.succeeded and (
            AUTHENTICATION_REFUSED in self.stderr or CONNECTION_CLOSED in self.stderr
        )

    def describe(self) -> str:
        certificate = "signed" if self.signed else "not signed by the portal"
        return (
            f"ssh {self.user}@{self.host} returned {self.returncode}, "
            f"key {certificate}\n"
            f"{self.stderr.strip()}\nsee {self.log}"
        )


@dataclass
class HopResult:
    """What a hop from a bastion to a backend did."""

    user: str
    bastion: str
    backend: str
    reached_bastion: bool
    returncode: int
    stdout: str
    stderr: str
    log: Path

    @property
    def succeeded(self) -> bool:
        """True when ob-ssh reported success."""
        return self.returncode == 0

    @property
    def output(self) -> str:
        """What the hop printed, whichever stream it printed it on.

        The recorder of the bastion runs ob-ssh under a pty, which merges
        the streams: the message of ssh saying why the hop failed arrives
        on stdout as often as on stderr.

        """
        return self.stdout + self.stderr

    @property
    def denied(self) -> bool:
        """True when the bastion opened a session and the hop was refused.

        ob-ssh fails for three different reasons: the portal refuses to
        issue a certificate, the backend refuses the certificate it was
        given, or the hop never happened because the backend is down, its
        name does not resolve, or ob-ssh is not installed. Only the first
        two are the answer of the fleet: a scenario asking about a refusal
        would otherwise pass on a broken fleet.

        """
        if not self.reached_bastion or self.succeeded:
            return False
        if _unreachable(self.output):
            return False
        return any(
            marker in self.output
            for marker in (
                AUTHENTICATION_REFUSED,
                CONNECTION_CLOSED,
                CERTIFICATE_REFUSED,
            )
        )

    def describe(self) -> str:
        bastion = "reached" if self.reached_bastion else "not reached"
        return (
            f"ob-ssh {self.backend} from {self.bastion} as {self.user} "
            f"(ssh exit {self.returncode}), bastion {bastion}\n"
            f"{self.stdout.strip()}\n{self.stderr.strip()}\nsee {self.log}"
        )


@dataclass
class SudoResult:
    """What a sudo attempt on a machine did."""

    user: str
    host: str
    status: int
    stdout: str
    stderr: str
    log: Path

    @property
    def succeeded(self) -> bool:
        """True when the machine ran sudo and it worked."""
        return self.status == 0

    @property
    def output(self) -> str:
        """What the attempt printed, whichever stream it printed it on.

        A sudo tried from a bastion goes through the recorder, which merges
        the streams: ssh says why it failed on stdout as often as on stderr.

        """
        return self.stdout + self.stderr

    @property
    def denied(self) -> bool:
        """True when the machine ran sudo and refused it.

        A machine that cannot be reached fails without deciding anything:
        it does not count as a refusal.

        """
        if self.succeeded:
            return False
        return not _unreachable(self.output)

    def describe(self) -> str:
        return (
            f"sudo as {self.user} on {self.host} (sudo exit {self.status})\n"
            f"{self.stdout.strip()}\n{self.stderr.strip()}\nsee {self.log}"
        )


def revocation_list(certificate: Path, ca_key: Path, output: Path) -> Path:
    """Write a KRL that revokes the certificate, signed by that CA."""
    args = [
        command.which("ssh-keygen"),
        "-k",
        "-f",
        str(output),
        "-s",
        str(ca_key),
        str(certificate),
    ]
    result = command.run(args)
    if result.returncode != 0 or not output.is_file():
        raise RuntimeError(f"Failed to write {output}: {result.stderr}")
    return output


@dataclass
class ServiceAccount:
    """An account the deployment serves a key for, with no portal session.

    Its key is the one named by the configuration ob-builder was given, and
    sshd serves it through its AuthorizedKeysCommand: the account logs in
    without the portal, and has nothing to answer when sudo asks it for the
    token of the portal.

    """

    name: str
    key: Path
    home: Path

    def connect(self, machine: Machine) -> SshResult:
        """Try to open a session on a machine with the key of the account."""
        log = self.home / f"connect-{machine.name}.log"
        result = self._run(machine, "true", log)
        LOGGER.debug(
            "ssh %s@%s returned %s", self.name, machine.name, result.returncode
        )
        return SshResult(
            user=self.name,
            host=machine.name,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            signed=False,
            log=log,
        )

    def sudo(self, machine: Machine) -> SudoResult:
        """Try to elevate as the account, as the fleet leaves it.

        Nothing is given to sudo: the account has no session on the portal,
        so the deployment either lets the elevation through, as it does
        before the setup, or refuses it.

        """
        log = self.home / f"sudo-{machine.name}.log"
        result = self._run(machine, "sudo -n true", log)
        LOGGER.debug(
            "sudo as %s on %s returned %s", self.name, machine.name, result.returncode
        )
        return SudoResult(
            user=self.name,
            host=machine.name,
            status=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            log=log,
        )

    def _run(
        self, machine: Machine, remote: str, log: Path
    ) -> subprocess.CompletedProcess[str]:
        """Run a command there with the key of the account, and only that one.

        The account has one identity, and the machine it is served by is
        named by the fleet: the ssh configuration of the users, which
        resolves an identity file per remote user, does not apply.

        """
        args = [
            command.which("ssh"),
            "-F",
            "/dev/null",
            "-i",
            str(self.key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"UserKnownHostsFile={self.home / 'known_hosts'}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={CONNECT_TIMEOUT}",
            f"{self.name}@{machine.ip}",
            remote,
        ]
        result = command.run(args, timeout=120.0)
        command.write_log(log, args, result)
        return result


@dataclass
class User:
    """A user owning a key pair, and a certificate when the portal signs it."""

    name: str
    home: Path

    @property
    def key(self) -> Path:
        return self.home / ".ssh" / f"id_{self.name}"

    @property
    def certificate(self) -> Path:
        return self.key.with_name(f"{self.key.name}-cert.pub")

    def ensure_key(self) -> None:
        """Create the key pair of the user if it doesn't exists.

        The private key is created without any passphrase."""
        self.key.parent.mkdir(parents=True, exist_ok=True)
        if self.key.exists():
            return
        result = command.run(
            [
                command.which("ssh-keygen"),
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"{self.name}@ob-lab-tests",
                "-f",
                str(self.key),
            ]
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to generate the key of {self.name}:\n"
                f"{result.stdout}\n{result.stderr}"
            )

    def public_key(self) -> str:
        return self.key.with_suffix(".pub").read_text().strip()

    def fingerprint(self) -> str:
        """Fingerprint of the key, unique to it.

        The portal refuses to sign twice under the same label, so the label
        of a signature cannot be the name of the user alone.

        """
        result = command.run(
            [command.which("ssh-keygen"), "-lf", str(self.key.with_suffix(".pub"))]
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to read the fingerprint of {self.key}\n"
                f"{result.stdout}\n{result.stderr}"
            )
        return result.stdout.split()[1]

    def save_certificate(self, certificate: str) -> None:
        self.certificate.write_text(certificate.strip() + "\n")

    def signed(self) -> bool:
        return self.certificate.is_file()

    def connect(self, host: str, ssh_config: Path) -> SshResult:
        """Try to open a session on the given machine."""
        log = self.home / f"connect-{host}.log"
        result = self._run(host, ssh_config, "true", log)
        LOGGER.debug("ssh %s@%s returned %s", self.name, host, result.returncode)
        return SshResult(
            user=self.name,
            host=host,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            signed=self.signed(),
            log=log,
        )

    def hop(self, bastion: str, backend: str, ssh_config: Path) -> HopResult:
        """Reach a backend from a bastion, the way a user of the fleet would.

        The bastion is asked for a session first: without one there is
        nothing to hop from, and a backend scenario would read the failure
        as the answer of the backend.

        """
        session = self.connect(bastion, ssh_config)
        log = self.home / f"hop-{bastion}-{backend}.log"
        result = self._run(
            bastion,
            ssh_config,
            f"ob-ssh {backend} true",
            log,
        )
        LOGGER.debug(
            "ob-ssh %s from %s as %s returned %s",
            backend,
            bastion,
            self.name,
            result.returncode,
        )
        return HopResult(
            user=self.name,
            bastion=bastion,
            backend=backend,
            reached_bastion=session.succeeded,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            log=log,
        )

    def sudo(self, host: str, token: str, ssh_config: Path) -> SudoResult:
        """Try to run sudo on the machine the user connects to."""
        return self._sudo(host, host, self._sudo_command(token), ssh_config)

    def sudo_command(
        self, host: str, command: str, token: str, ssh_config: Path
    ) -> SudoResult:
        """Run one command through sudo, with the token of the portal."""
        return self._sudo(host, host, f"echo {token} | sudo -S {command}", ssh_config)

    def sudo_from(
        self, bastion: str, backend: str, token: str, ssh_config: Path
    ) -> SudoResult:
        """Try to run sudo on a backend the user reaches from a bastion."""
        command = self._sudo_command(token)
        return self._sudo(bastion, backend, f"ob-ssh {backend} '{command}'", ssh_config)

    @staticmethod
    def _sudo_command(token: str) -> str:
        """The command that gives sudo the one-time token of the portal.

        sudo asks for a password there; the token is what it expects, read
        from stdin so nothing waits on a terminal.

        """
        return f"echo {token} | sudo -S true"

    def _sudo(
        self, session_host: str, sudo_host: str, remote: str, ssh_config: Path
    ) -> SudoResult:
        """Run sudo where the session leads, and read its status.

        The session recorder of the bastion hands the exit status of the
        command back to ssh, so sudo's own status is the one read here.

        """
        log = self.home / f"sudo-{sudo_host}.log"
        result = self._run(session_host, ssh_config, remote, log)
        status = result.returncode
        LOGGER.debug("sudo as %s on %s returned %s", self.name, sudo_host, status)
        return SudoResult(
            user=self.name,
            host=sudo_host,
            status=status,
            stdout=result.stdout,
            stderr=result.stderr,
            log=log,
        )

    def _run(
        self, host: str, ssh_config: Path, remote: str, log: Path
    ) -> subprocess.CompletedProcess[str]:
        args = [
            command.which("ssh"),
            "-F",
            str(ssh_config),
            "-o",
            f"UserKnownHostsFile={self.home / '.ssh' / 'known_hosts'}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={CONNECT_TIMEOUT}",
            f"{self.name}@{host}",
            remote,
        ]
        result = command.run(args, timeout=120.0)
        command.write_log(log, args, result)
        return result

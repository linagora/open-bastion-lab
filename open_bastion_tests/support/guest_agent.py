"""Root on a guest, through the QEMU guest agent.

A deployment in maximum security takes sudo over: once ``ob-bastion-setup``
has run, no local account can elevate — the maintainer one included. A
scenario that has to read a root-owned file (the sshd drop-in serving the
service accounts, the list of bastions a backend accepts, the id of a
bastion) therefore cannot go through SSH.

The guest agent answers on its virtio channel, before PAM and sshd, and
everything it runs is root's. The machines of the fleet run it: the base
image enables ``qemu-guest-agent``, and a domain is named like its machine.

"""

from dataclasses import dataclass

import base64
import json
import logging
import shlex
import time

from open_bastion_tests.support import command

LOGGER = logging.getLogger(__name__)

# How long the agent is given to answer one request
AGENT_TIMEOUT = 60.0

# How long a command run in the guest is given to finish
COMMAND_TIMEOUT = 120.0

# How often the end of a command is asked for
POLL_INTERVAL = 0.2


class AgentError(RuntimeError):
    """The guest agent could not be reached, or refused the request."""


@dataclass
class AgentResult:
    """What a command run in a guest printed."""

    domain: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    def describe(self) -> str:
        return (
            f"{' '.join(self.argv)} in {self.domain} returned "
            f"{self.returncode}\n{self.stdout.strip()}\n{self.stderr.strip()}"
        )


def _request(domain: str, payload: dict, *, timeout: float = AGENT_TIMEOUT) -> dict:
    """One request to the agent of a domain, its answer unwrapped."""
    args = [
        command.which("virsh"),
        "qemu-agent-command",
        domain,
        json.dumps(payload),
    ]
    result = command.run(args, timeout=timeout)
    if result.returncode != 0:
        raise AgentError(
            f"The guest agent of {domain} did not answer "
            f"({result.returncode}): {result.stderr.strip()}"
        )
    try:
        answer = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AgentError(
            f"The guest agent of {domain} answered something else than JSON: "
            f"{result.stdout.strip()}"
        ) from error
    if "error" in answer:
        detail = answer["error"].get("desc", answer["error"])
        raise AgentError(f"The guest agent of {domain} refused: {detail}")
    return answer["return"]


def _decode(encoded: str | None) -> str:
    if not encoded:
        return ""
    return base64.b64decode(encoded).decode(errors="replace")


def start(
    domain: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
) -> int:
    """Start a command as root in a guest, and answer the pid it runs as.

    A command whose progress matters to the caller — an installer that waits
    for the portal to approve it — is started here and waited on separately,
    so that what it waits for can happen in between.

    """
    LOGGER.debug("Running %s in %s as root", " ".join(argv), domain)
    arguments: dict = {"path": argv[0], "arg": argv[1:], "capture-output": True}
    if env:
        arguments["env"] = [f"{name}={value}" for name, value in env.items()]
    started = _request(
        domain,
        {"execute": "guest-exec", "arguments": arguments},
    )
    return started["pid"]


def wait(
    domain: str, pid: int, argv: list[str], *, timeout: float = COMMAND_TIMEOUT
) -> AgentResult:
    """What a command started in a guest printed, once it has finished."""
    deadline = time.monotonic() + timeout
    while True:
        status = _request(
            domain, {"execute": "guest-exec-status", "arguments": {"pid": pid}}
        )
        if status.get("exited"):
            if status.get("out-truncated"):
                raise AgentError(
                    f"The output of {' '.join(argv)} in {domain} was truncated"
                )
            return AgentResult(
                domain=domain,
                argv=argv,
                returncode=status.get("exitcode", 1),
                stdout=_decode(status.get("out-data")),
                stderr=_decode(status.get("err-data")),
            )
        if time.monotonic() > deadline:
            raise AgentError(f"{' '.join(argv)} in {domain} did not finish")
        time.sleep(POLL_INTERVAL)


def run(
    domain: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = COMMAND_TIMEOUT,
) -> AgentResult:
    """Run a command as root in a guest, and wait for it.

    The agent runs commands asynchronously: it answers a pid, and the status
    of that pid is asked for until the command has finished.

    """
    pid = start(domain, argv, env=env)
    return wait(domain, pid, argv, timeout=timeout)


def shell(domain: str, script: str, *, timeout: float = COMMAND_TIMEOUT) -> AgentResult:
    """Run a shell script as root in a guest."""
    return run(domain, ["/bin/sh", "-c", script], timeout=timeout)


def exists(domain: str, path: str) -> bool:
    """Whether a path exists in a guest, as root sees it."""
    return shell(domain, f"test -e {shlex.quote(path)}").succeeded


def write_text(domain: str, path: str, content: str, *, mode: int = 0o600) -> None:
    """Leave a file in a guest, as root.

    The file does not go through the guest's shell: an installer is tens of
    kilobytes, which a command line carries badly and a heredoc worse. The
    agent writes it, and the mode is set afterwards because the agent creates
    the file 0600.

    """
    handle = _request(
        domain,
        {"execute": "guest-file-open", "arguments": {"path": path, "mode": "w"}},
    )
    try:
        _request(
            domain,
            {
                "execute": "guest-file-write",
                "arguments": {
                    "handle": handle,
                    "buf-b64": base64.b64encode(content.encode()).decode(),
                },
            },
        )
    finally:
        _request(
            domain, {"execute": "guest-file-close", "arguments": {"handle": handle}}
        )
    result = shell(domain, f"chmod {mode:04o} -- {shlex.quote(path)}")
    if not result.succeeded:
        raise AgentError(
            f"Cannot set the mode of {path} in {domain}: {result.stderr.strip()}"
        )


def read_text(domain: str, path: str) -> str:
    """What a file holds, as root sees it."""
    result = shell(domain, f"cat -- {shlex.quote(path)}")
    if not result.succeeded:
        raise AgentError(f"Cannot read {path} in {domain}: {result.stderr.strip()}")
    return result.stdout

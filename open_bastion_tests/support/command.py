"""Run external commands and keep what they printed."""

from pathlib import Path
import logging
import os
import shutil
import subprocess

LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 900.0


def which(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"Missing command {name}, is the environment ready?")
    return path


def run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    stdin: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    log: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command without letting it talk to the terminal.

    With a log file, the output is written as it comes, so a command that
    takes minutes can be watched while it runs.

    """
    LOGGER.debug("Running %s", " ".join(args))
    if log is not None:
        return _run_logged(
            args, env=env, cwd=cwd, stdin=stdin, timeout=timeout, log=log
        )
    return subprocess.run(
        args,
        env=env,
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _run_logged(
    args: list[str],
    *,
    env: dict[str, str] | None,
    cwd: Path | None,
    stdin: str | None,
    timeout: float,
    log: Path,
) -> subprocess.CompletedProcess[str]:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        stream.write(f"$ {' '.join(args)}\n")
        stream.flush()
        return subprocess.run(
            args,
            env=env,
            cwd=cwd,
            input=stdin,
            stdout=stream,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )


def environment(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update(extra)
    return env


def write_log(
    path: Path, args: list[str], result: subprocess.CompletedProcess[str]
) -> None:
    """Leave the output of a command where a failing test can be diagnosed."""
    path.write_text(
        f"$ {' '.join(args)}\n"
        f"status: {result.returncode}\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}\n"
    )

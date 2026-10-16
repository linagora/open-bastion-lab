"""Helpers shared by the test support modules."""

from pathlib import Path


def public_key(key: Path) -> Path:
    """Path of the public half of a key pair."""
    return Path(f"{key}.pub")

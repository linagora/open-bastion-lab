from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from platformdirs import user_config_path, user_data_path
from typing import cast, Any

import dataclasses
import logging
import tomllib

from open_bastion_lab.model import Role

LOGGER = logging.getLogger(__name__)

APP_NAME = "open-bastion-lab"
APP_AUTHOR = "open-bastion-lab"

CONFIG_FILENAME = "config.toml"


@dataclass
class Config:
    # initialized through user config file or command line
    fleet: str

    # initialized through user config file
    authorized_keys: list[str] = field(default_factory=list)
    hypervisor: str = "libvirt"
    imds_host: str = "192.168.122.1"
    imds_port: int = 8001

    # initialized through fleet config file
    hosts: dict[Role, list[str]] = field(default_factory=dict, init=False)

    @classmethod
    def from_any_keywords(cls, **kwargs):
        names = {f.name for f in dataclasses.fields(cls)}
        config = cls(**{k: v for k, v in kwargs.items() if k in names and k != "hosts"})

        for role, names in kwargs.get("hosts", {}).items():
            config.hosts[Role(role)] = names

        return config


def _raw_user_config() -> dict[str, Any]:
    path = user_config_path(APP_NAME, APP_AUTHOR) / CONFIG_FILENAME
    LOGGER.debug("Reading user configuration file %s", path)
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(*, fleet: str) -> Config:
    """Returns the configuration read from user and fleet
    configuration files.

    """
    raw = _raw_user_config()

    fleet = fleet if len(fleet) > 0 else cast(str, raw.get("fleet", ""))
    if len(fleet) == 0:
        raise RuntimeError("Missing fleet name")

    fleet_config = files("open_bastion_lab") / "data" / "fleet" / fleet / "config.toml"
    if not fleet_config.is_file():
        raise RuntimeError(f"No fleet with name {fleet}")

    raw.update(tomllib.loads(fleet_config.read_text()))

    config = Config.from_any_keywords(**raw)
    return config

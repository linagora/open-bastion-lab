from enum import StrEnum


class Role(StrEnum):
    BASTION = "bastion"
    BACKEND = "backend"
    STANDALONE = "standalone"

import argparse
import asyncio
import logging

from open_bastion_lab.config import Config
from open_bastion_lab.config import load_config
from open_bastion_lab.runner import COMMANDS, DEFAULT_SNAPSHOT, run

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ob-lab")
    parser.add_argument(
        "-f",
        "--fleet",
        type=str,
        default="",
        help="fleet to deploy, optional",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="enable debug output",
    )
    parser.add_argument(
        "-s",
        "--snapshot",
        type=str,
        default=DEFAULT_SNAPSHOT,
        help=f"snapshot to create or restore (default: {DEFAULT_SNAPSHOT})",
    )
    parser.add_argument(
        "command",
        choices=COMMANDS,
        help="command to run",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.debug == True:
        logging.basicConfig(level=logging.DEBUG)

    config: Config = load_config(fleet=args.fleet)

    return asyncio.run(run(args.command, config, args.snapshot))

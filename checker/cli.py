"""The `checker` command. Subcommands arrive with the features they drive."""

import argparse

from checker import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checker",
        description="Read-only compromise checker for RHEL and Ubuntu servers.",
    )
    parser.add_argument("--version", action="version", version=f"checker {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print(f"checker {__version__} (no commands yet)")
    return 0

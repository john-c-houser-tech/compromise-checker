"""The `checker` command. Subcommands arrive with the features they drive."""

import argparse
import asyncio
import sys
from collections.abc import Callable

from pydantic import ValidationError

from checker import __version__
from checker.inventory import Host, load_inventory, save_inventory
from checker.transport import TransportError, fetch_host_key, trust_host_key


def cmd_hosts_add(args: argparse.Namespace) -> int:
    inventory = load_inventory()
    try:
        host = Host(
            name=args.name,
            address=args.address,
            port=args.port,
            user=args.user,
            auth=args.auth,
            key_path=args.key,
            sudo=args.sudo,
            password_source=args.password_source,
            group=args.group,
            python=args.python,
        )
        inventory.add(host)
    except (ValidationError, ValueError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    save_inventory(inventory)
    print(f"Added {host.name} ({host.user}@{host.address}:{host.port}).")
    print(f"Next: `checker trust {host.name}` to check and accept its host key.")
    return 0


def cmd_hosts_list(args: argparse.Namespace) -> int:
    hosts = load_inventory().hosts
    if not hosts:
        print("No hosts yet. Add one with `checker hosts add`.")
        return 0
    for host in hosts:
        group = f"  [{host.group}]" if host.group else ""
        print(
            f"{host.name:20} {host.user}@{host.address}:{host.port}"
            f"  auth={host.auth} sudo={host.sudo}{group}"
        )
    return 0


def cmd_hosts_remove(args: argparse.Namespace) -> int:
    inventory = load_inventory()
    try:
        inventory.remove(args.name)
    except KeyError as exc:
        print(f"checker: {exc.args[0]}", file=sys.stderr)
        return 2
    save_inventory(inventory)
    print(f"Removed {args.name}.")
    return 0


def cmd_trust(args: argparse.Namespace, ask: Callable[[str], str] = input) -> int:
    try:
        host = load_inventory().get(args.name)
    except KeyError as exc:
        print(f"checker: {exc.args[0]}", file=sys.stderr)
        return 2
    try:
        check = asyncio.run(fetch_host_key(host))
    except TransportError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1

    print(f"{host.name} ({host.address}:{host.port}) offers a {check.key_type} host key:")
    print(f"  {check.fingerprint}")
    if check.status == "same":
        print("This key is already trusted. Nothing to do.")
        return 0
    if check.status == "changed":
        print("WARNING: this is NOT the key trusted before:", file=sys.stderr)
        for fingerprint in check.known_fingerprints:
            print(f"  previously {fingerprint}", file=sys.stderr)
        print(
            "A changed key can mean the server was rebuilt, or that someone is intercepting"
            " the connection. Confirm the new key with the server's administrator.",
            file=sys.stderr,
        )
        if not args.replace:
            print("Not changed. Re-run with --replace once you have confirmed it.", file=sys.stderr)
            return 1

    if args.expect:
        if args.expect != check.fingerprint:
            print(f"checker: fingerprint does not match --expect {args.expect}", file=sys.stderr)
            return 1
    else:
        print("Compare it with the server's own fingerprint, for example from")
        print("  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub   (run on the server)")
        if ask("Trust this key? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Not trusted.")
            return 1
    trust_host_key(host, check)
    print(f"Trusted. {host.name} can now be checked.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checker",
        description="Read-only compromise checker for RHEL and Ubuntu servers.",
    )
    parser.add_argument("--version", action="version", version=f"checker {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    hosts = commands.add_parser("hosts", help="manage the inventory of hosts")
    hosts_commands = hosts.add_subparsers(dest="hosts_command", metavar="ACTION", required=True)

    add = hosts_commands.add_parser("add", help="add a host")
    add.add_argument("name", help="a short name for the host, e.g. web01")
    add.add_argument("--address", required=True, help="hostname or IP address")
    add.add_argument("--port", type=int, default=22)
    add.add_argument("--user", required=True, help="the account to log in as")
    add.add_argument("--auth", choices=["agent", "key", "password"], default="agent")
    add.add_argument("--key", help="private key file, with --auth key")
    add.add_argument(
        "--sudo",
        choices=["root", "nopasswd", "password"],
        default="nopasswd",
        help="root: log in as root; nopasswd: sudo without a password; password: sudo asks",
    )
    add.add_argument("--password-source", choices=["prompt", "keyring"], default="prompt")
    add.add_argument("--group", help="a group name, e.g. web")
    add.add_argument("--python", default="python3", help="the interpreter on the host")
    add.set_defaults(handler=cmd_hosts_add)

    hosts_commands.add_parser("list", help="list hosts").set_defaults(handler=cmd_hosts_list)

    remove = hosts_commands.add_parser("remove", help="remove a host")
    remove.add_argument("name")
    remove.set_defaults(handler=cmd_hosts_remove)

    trust = commands.add_parser("trust", help="check and accept a host's SSH host key")
    trust.add_argument("name")
    trust.add_argument("--expect", metavar="SHA256:…", help="accept only this fingerprint")
    trust.add_argument("--replace", action="store_true", help="replace a changed key")
    trust.set_defaults(handler=cmd_trust)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        print(f"checker {__version__}")
        parser.print_help()
        return 0
    return handler(args)

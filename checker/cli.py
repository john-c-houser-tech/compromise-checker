"""The `checker` command. Subcommands arrive with the features they drive."""

import argparse
import asyncio
import json
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from checker import __version__
from checker.collect import collect_hosts
from checker.credentials import password_for
from checker.evidence import (
    EvidenceError,
    Store,
    check_sidecar,
    database_file,
    file_sha256,
    initialise,
    judge,
    load_config,
    load_identity,
    open_bundle,
    open_text,
)
from checker.inventory import Host, home, inventory_transaction, load_inventory
from checker.transport import TransportError, fetch_host_key, trust_host_key


def cmd_hosts_add(args: argparse.Namespace) -> int:
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
        with inventory_transaction() as inventory:
            inventory.add(host)
    except (ValidationError, ValueError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
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
    try:
        with inventory_transaction() as inventory:
            inventory.remove(args.name)
    except KeyError as exc:
        print(f"checker: {exc.args[0]}", file=sys.stderr)
        return 2
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
    if check.status == "same" and args.expect in (None, check.fingerprint):
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


def cmd_init(args: argparse.Namespace) -> int:
    base = home()
    try:
        config, identity_path = initialise(base, args.recipient)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    print(f"Set up in {base}.")
    print(f"Evidence is encrypted to: {config.recipients[0]}")
    if identity_path:
        print(f"The private key is in {identity_path}.")
        print("BACK IT UP somewhere safe and separate: without it, stored evidence")
        print("cannot be read, by you or anyone else.")
    else:
        print("Its private key is not on this machine; use --identity to read bundles.")
    print("Next: `checker hosts add`, then `checker trust`, then `checker collect`.")
    return 0


def _select_hosts(args: argparse.Namespace) -> list[Host]:
    inventory = load_inventory()
    if args.all:
        return list(inventory.hosts)
    if args.group:
        return [host for host in inventory.hosts if host.group == args.group]
    return [inventory.get(name) for name in args.names]


def cmd_collect(args: argparse.Namespace) -> int:
    base = home()
    try:
        config = load_config(base)
        hosts = _select_hosts(args)
    except (EvidenceError, KeyError) as exc:
        print(f"checker: {exc.args[0] if isinstance(exc, KeyError) else exc}", file=sys.stderr)
        return 2
    if not hosts:
        print("checker: no hosts selected", file=sys.stderr)
        return 2
    outcomes = asyncio.run(
        collect_hosts(
            base,
            config,
            hosts,
            days=args.days,
            parallel=args.parallel,
            password_provider=password_for,
        )
    )
    for outcome in outcomes:
        note = f"  ({outcome.error})" if outcome.error else ""
        print(f"{outcome.host:20} {outcome.status:12} {outcome.bundle_id or '-'}{note}")
    succeeded = len(outcomes) == len(hosts) and all(
        outcome.status in ("complete", "partial") and outcome.error is None for outcome in outcomes
    )
    return 0 if succeeded else 1


def _identity(args: argparse.Namespace, base: Path):
    path = args.identity or load_config(base).identity_file
    if not path:
        raise EvidenceError("no evidence key here; pass --identity PATH")
    return load_identity(Path(path))


def cmd_bundle_list(args: argparse.Namespace) -> int:
    store = Store(database_file(home()))
    rows = store.bundles(args.host)
    store.close()
    if not rows:
        print("No bundles yet.")
    for row in rows:
        print(f"{row['id']:48} {row['status']:10} {row['plaintext_bytes']:>12,} bytes")
    return 0


def cmd_bundle_show(args: argparse.Namespace) -> int:
    base = home()
    store = Store(database_file(base))
    try:
        row = store.bundle(args.bundle)
        observer = open_bundle(Path(row["path"]), _identity(args, base))
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    observer.status()
    store.custody(row["id"], "viewed")
    store.close()
    summary = observer.summary
    manifest, trailer = summary.manifest or {}, summary.trailer or {}
    host = manifest.get("host", {})
    print(f"Bundle     {row['id']}")
    print(f"Status     {row['status']}")
    print(f"Host       {host.get('hostname')}  {host.get('os_pretty_name')}  {host.get('kernel')}")
    print(f"Collector  {manifest.get('collector_version')}  sha256 {row['collector_sha256']}")
    print(f"Started    {manifest.get('started_at')}  ({trailer.get('duration_seconds')} s)")
    for name, result in (trailer.get("modules") or {}).items():
        print(f"  module {name:16} {result['status']:8} {result['seconds']} s")
    for source in summary.sources:
        flags = []
        if source.get("truncated"):
            flags.append(f"truncated ({source.get('truncated_reason')})")
        if source.get("masked"):
            masked = ", ".join(f"{k} {v}" for k, v in source["masked"].items())
            flags.append(f"masked: {masked}")
        if source.get("error"):
            flags.append(f"error: {source['error']}")
        extra = f"  [{'; '.join(flags)}]" if flags else ""
        print(f"  source {source.get('name')}  {source.get('bytes'):,} bytes{extra}")
    for error in summary.errors:
        print(f"  error  {error['module']}: {error['message']}")
    return 0


def cmd_bundle_verify(args: argparse.Namespace) -> int:
    base = home()
    store = Store(database_file(base))
    try:
        row = store.bundle(args.bundle)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    path = Path(row["path"])
    checks: list[tuple[str, bool]] = []
    try:
        actual = file_sha256(path)
    except OSError as exc:  # missing, unreadable, a directory: a failed check, not a crash
        actual = None
        checks.append((f"encrypted file readable ({type(exc).__name__})", False))
    else:
        checks.append(
            ("encrypted file matches its recorded hash", actual == row["ciphertext_sha256"])
        )
    checks.extend(check_sidecar(path.with_suffix(".json"), row))
    try:
        identity = _identity(args, base)
    except EvidenceError as exc:
        print(f"note: content not checked: {exc}")
        identity = None
    if identity is not None and actual is not None:
        try:
            observer = open_bundle(path, identity)
            session = json.loads(open_text(row["session"], identity) or "{}")
            status, _ = judge(
                observer.status(),
                observer.summary.manifest,
                row["run_id"],
                session.get("exit_status"),
            )
            checks.append(
                (
                    "decrypted content matches its recorded hash",
                    observer.sha256.hexdigest() == row["plaintext_sha256"],
                )
            )
            checks.append(("content gives the recorded status", status == row["status"]))
        except EvidenceError as exc:
            checks.append((f"decrypts ({exc})", False))
    for label, ok in checks:
        print(f"{'ok  ' if ok else 'FAIL'}  {label}")
    passed = all(ok for _, ok in checks)
    store.custody(row["id"], "verified", {"passed": passed, "checks": dict(checks)})
    store.close()
    print("Verified." if passed else "Verification FAILED.")
    return 0 if passed else 1


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

    init = commands.add_parser("init", help="set up: evidence key, database, configuration")
    init.add_argument(
        "--recipient",
        metavar="AGE_PUBLIC_KEY",
        help="encrypt evidence to this key (its private half kept elsewhere)",
    )
    init.set_defaults(handler=cmd_init)

    collect = commands.add_parser("collect", help="collect evidence from hosts")
    which = collect.add_mutually_exclusive_group(required=True)
    which.add_argument("names", nargs="*", default=[], help="host names")
    which.add_argument("--group", help="every host in this group")
    which.add_argument("--all", action="store_true", help="every host in the inventory")
    collect.add_argument("--days", type=int, default=30, help="look-back window (default 30)")
    collect.add_argument("--parallel", type=int, default=5, help="hosts at a time (default 5)")
    collect.set_defaults(handler=cmd_collect)

    bundle = commands.add_parser("bundle", help="list, show and verify stored evidence")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", metavar="ACTION", required=True)
    listing = bundle_commands.add_parser("list", help="list bundles")
    listing.add_argument("--host")
    listing.set_defaults(handler=cmd_bundle_list)
    for name, handler, text in (
        ("show", cmd_bundle_show, "decrypt and summarise a bundle (no content shown)"),
        ("verify", cmd_bundle_verify, "check a bundle's hashes and content"),
    ):
        action = bundle_commands.add_parser(name, help=text)
        action.add_argument("bundle", help="bundle id")
        action.add_argument("--identity", help="the evidence private key file")
        action.set_defaults(handler=handler)
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

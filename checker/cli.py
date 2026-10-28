"""The `checker` command. Subcommands arrive with the features they drive."""

import argparse
import asyncio
import json
import sqlite3
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from pydantic import ValidationError

from checker import __version__
from checker.analysis import load_events, parse_bundle, store_parsed
from checker.assess import analyze, prior_for
from checker.baseline import accept, changes, usable_bundles
from checker.checks import BANDS, CATEGORIES
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
from checker.inventory import Host, home, hosts_file, inventory_transaction, load_inventory
from checker.purge import execute, expired_count, leftovers, parse_before
from checker.purge import plan as purge_plan
from checker.report import write_report
from checker.scoring import percent
from checker.transport import TransportError, fetch_host_key, trust_host_key
from checker.whitelist import WhitelistError, check_all
from checker.whitelist import for_host as whitelist_for_host

# What `checker init --home-text` means, as `init` reports it.
HOME_TEXT = {
    "off": "not collected (hashes only)",
    "privileged": "collected, masked, for root, service and administrator accounts",
    "all": "collected, masked, for every account",
}


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
            web_roots=args.web_root,
            prior=args.prior,
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
        config, identity_path = initialise(base, args.recipient, args.home_text)
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
    print(
        f"Text of start-up files and user units in home directories: {HOME_TEXT[config.home_text]}"
    )
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
    _expired_notice(base)
    return 0 if succeeded else 1


def _inventory_for_priors():
    """The inventory, for hosts' priors; an invalid one is an error the
    operator can read, not a traceback."""
    try:
        return load_inventory()
    except (ValidationError, ValueError) as exc:
        raise EvidenceError(f"the inventory ({hosts_file()}) is invalid: {exc}") from None


def cmd_whitelist_check(args: argparse.Namespace) -> int:
    """Every file valid; with a host, its merged set, widest layer last."""
    base = home()
    try:
        inventory = _inventory_for_priors()
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    errors = check_all(base, inventory)
    for error in errors:
        print(f"checker: {error}", file=sys.stderr)
    if errors:
        return 1
    if not args.host:
        print("Every whitelist file is valid.")
        return 0
    try:
        merged = _whitelist_for(base, args.host, inventory)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    if merged is None or not merged.rules:
        print(f"No whitelist rules apply to {args.host}.")
    if merged is None:
        return 0
    today = datetime.now(UTC).date()
    for placed in merged.rules:
        rule = placed.rule
        expired = rule.expires != "never" and rule.expires < today
        fields = ", ".join(f"{k}={v}" for k, v in rule.match.entity_fields().items())
        print(
            f"{placed.layer:20} {rule.id:30} {rule.match.check}"
            + (f"/{rule.match.variant}" if rule.match.variant else "")
            + (f" [{fields}]" if fields else " [broad]")
            + (f" EXPIRED {rule.expires}" if expired else f" until {rule.expires}")
        )
        print(f"{'':20} {rule.reason}  ({rule.owner})")
    for item in merged.disabled:
        print(f"{item['by']:20} switched off {item['id']}: {item['reason']}  ({item['owner']})")
    return 0


def _whitelist_for(base: Path, host: str, inventory):
    """A host's merged whitelist; an invalid file stops the analysis, with
    the file and line (DESIGN.md §9: never analyse with a broken set)."""
    try:
        return whitelist_for_host(base, host, inventory)
    except WhitelistError as exc:
        raise EvidenceError(f"whitelist: {exc}") from None


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
        identity = _identity(args, base)
        observer = open_bundle(Path(row["path"]), identity)
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
    problem = open_text(row["problem"], identity)
    if problem:
        print(f"Problem    {problem}")
    print(f"Host       {host.get('hostname')}  {host.get('os_pretty_name')}  {host.get('kernel')}")
    print(f"Collector  {manifest.get('collector_version')}  sha256 {row['collector_sha256']}")
    print(f"Started    {manifest.get('started_at')}  ({trailer.get('duration_seconds')} s)")
    for name, result in (trailer.get("modules") or {}).items():
        print(f"  module {name:16} {result['status']:8} {result['seconds']} s")
    for source in summary.as_dict()["sources"]:
        flags = []
        if source.get("truncated"):
            flags.append(f"truncated ({source.get('truncated_reason')})")
        if source.get("masked"):
            masked = ", ".join(f"{k} {v}" for k, v in source["masked"].items())
            flags.append(f"masked: {masked}")
        if source.get("error"):
            flags.append(f"error: {source['error']}")
        extra = f"  [{'; '.join(flags)}]" if flags else ""
        size = "unknown size" if source.get("bytes") is None else f"{source['bytes']:,} bytes"
        print(f"  source {source.get('name')}  {size}{extra}")
    for error in summary.errors:
        print(f"  error  {error['module']}: {error['message']}")
    for kind, count in summary.dropped.items():
        print(f"  ({count} more {kind.replace('_', ' ')} not listed)")
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
    identity = None
    if args.identity or load_config(base).identity_file:
        try:
            identity = _identity(args, base)
        except EvidenceError as exc:
            # A key was asked for but couldn't be used: that's a failure, not
            # a quiet downgrade to checking hashes only.
            checks.append((f"evidence key loaded ({exc})", False))
    else:
        print("note: no evidence key here, so the content was not checked")
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
    add.add_argument(
        "--web-root",
        action="append",
        metavar="DIR",
        help=(
            "a web root to list for web shells (repeatable); replaces the defaults"
            " /var/www, /srv/www, /srv/http and /usr/share/nginx/html"
        ),
    )
    add.add_argument(
        "--prior",
        type=float,
        help=(
            "this host's prior probability of compromise, e.g. 0.05"
            " (default: its group's, else the configuration's)"
        ),
    )
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
    init.add_argument(
        "--home-text",
        choices=sorted(HOME_TEXT),
        default="off",
        help=(
            "also collect the masked text of start-up files and user units in home"
            " directories: off (hashes only, the default), privileged (root, service"
            " and administrator accounts) or all"
        ),
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
    events = commands.add_parser("events", help="parse a bundle into events and list them")
    events.add_argument("bundle", help="bundle id")
    events.add_argument("--type", help="only events whose type starts with this, e.g. ssh.")
    events.add_argument("--own", action="store_true", help="include this tool's own session")
    events.add_argument("--reparse", action="store_true", help="parse again even if stored")
    events.add_argument("--identity", help="the evidence private key file")
    events.set_defaults(handler=cmd_events)
    analysing = commands.add_parser(
        "analyze", help="run the checks on a host's latest bundle and list the findings"
    )
    target = analysing.add_mutually_exclusive_group(required=True)
    target.add_argument("host", nargs="?")
    target.add_argument("--all", action="store_true", help="every host with a usable bundle")
    analysing.add_argument("--bundle", help="this bundle rather than the host's latest")
    analysing.add_argument("--info", action="store_true", help="also list informational findings")
    analysing.add_argument(
        "--suppressed", action="store_true", help="also list findings the whitelist suppressed"
    )
    analysing.add_argument("--identity", help="the evidence private key file")
    analysing.set_defaults(handler=cmd_analyze)
    reporting = commands.add_parser(
        "report", help="write the confidential HTML report for hosts' latest bundles"
    )
    chosen = reporting.add_mutually_exclusive_group(required=True)
    chosen.add_argument("host", nargs="?")
    chosen.add_argument("--all", action="store_true", help="every host with a usable bundle")
    reporting.add_argument("--bundle", help="this bundle rather than the host's latest")
    reporting.add_argument("--output", help="the file to write (default: reports/ in the home)")
    reporting.add_argument("--identity", help="the evidence private key file")
    reporting.set_defaults(handler=cmd_report)
    changed = commands.add_parser(
        "changes", help="what changed on a host since its previous bundle and its baseline"
    )
    changed.add_argument("host")
    changed.add_argument("--bundle", help="this bundle rather than the host's latest")
    changed.add_argument("--all", action="store_true", help="list every item, not the first 20")
    changed.add_argument("--identity", help="the evidence private key file")
    changed.set_defaults(handler=cmd_changes)
    baseline = commands.add_parser("baseline", help="show or accept a host's baseline")
    baseline_commands = baseline.add_subparsers(
        dest="baseline_command", metavar="ACTION", required=True
    )
    show = baseline_commands.add_parser("show", help="a host's baselines, oldest first")
    show.add_argument("host")
    show.add_argument("--identity", help="the evidence private key file (to show reasons)")
    show.set_defaults(handler=cmd_baseline_show)
    accepting = baseline_commands.add_parser(
        "accept", help="make a reviewed bundle (by default the latest) the host's baseline"
    )
    accepting.add_argument("host")
    accepting.add_argument("--reason", required=True, help="why the change is accepted")
    accepting.add_argument("--bundle", help="this bundle rather than the host's latest")
    accepting.add_argument("--identity", help="the evidence private key file")
    accepting.set_defaults(handler=cmd_baseline_accept)
    whitelisting = commands.add_parser("whitelist", help="check the whitelist files")
    whitelist_commands = whitelisting.add_subparsers(
        dest="whitelist_command", metavar="ACTION", required=True
    )
    checking = whitelist_commands.add_parser(
        "check", help="validate every whitelist file; with a host, show its merged rules"
    )
    checking.add_argument("host", nargs="?")
    checking.set_defaults(handler=cmd_whitelist_check)
    purging = commands.add_parser(
        "purge", help="delete stored evidence for a host, before a date, or past retention"
    )
    purging.add_argument("host", nargs="?", help="only this host (alone: all of its evidence)")
    purging.add_argument("--before", metavar="DATE", help="bundles collected before this date")
    purging.add_argument(
        "--expired",
        action="store_true",
        help="bundles past the retention period (each host's current baseline is kept)",
    )
    purging.add_argument(
        "--dry-run", action="store_true", help="show what would go, delete nothing"
    )
    purging.add_argument("--yes", action="store_true", help="don't ask before deleting")
    purging.set_defaults(handler=cmd_purge)
    return parser


SHOWN = 20  # items listed per kind and section without --all


def cmd_report(args: argparse.Namespace) -> int:
    """Write the HTML report: owner-only, confidential (policy §8)."""
    base = home()
    store = Store(database_file(base))
    try:
        if args.all:
            if args.bundle:
                raise EvidenceError("--bundle names one host's bundle: give the host instead")
            hosts = [h for h in store.hosts() if usable_bundles(store, h)]
            if not hosts:
                raise EvidenceError("no host has a usable bundle yet: collect first")
        else:
            hosts = [args.host]
        inventory = _inventory_for_priors()
        whitelists = {h: _whitelist_for(base, h, inventory) for h in hosts}
        path = write_report(
            store,
            hosts,
            _identity(args, base),
            load_config(base).recipients,
            base / "reports",
            args.bundle,
            Path(args.output) if args.output else None,
            partial(prior_for, config=load_config(base), inventory=inventory),
            whitelists.get,
        )
    except (EvidenceError, OSError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"Report written to {path}")
    print(
        "It is confidential: it describes weaknesses an attacker could use."
        " Handle it like the evidence."
    )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Run the checks and list the findings, most serious first, with
    what the collection couldn't see."""
    base = home()
    store = Store(database_file(base))
    status = 0
    try:
        identity = _identity(args, base)
        config = load_config(base)
        recipients = config.recipients
        inventory = _inventory_for_priors()
        if args.all:
            hosts = [h for h in store.hosts() if usable_bundles(store, h)]
            if args.bundle:
                raise EvidenceError("--bundle names one host's bundle: give the host instead")
            if not hosts:
                raise EvidenceError("no host has a usable bundle yet: collect first")
        else:
            hosts = [args.host]
        # All of them before any analysis: one broken file stops the run.
        whitelists = {h: _whitelist_for(base, h, inventory) for h in hosts}
        for number, host in enumerate(hosts):
            if number:
                print()
            try:
                prior = prior_for(host, config, inventory)
                _print_assessment(
                    analyze(
                        store, host, identity, recipients, args.bundle, prior, whitelists[host]
                    ),
                    args,
                )
            except EvidenceError as exc:
                print(f"checker: {host}: {exc}", file=sys.stderr)
                status = 1
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    _expired_notice(base)
    return status


HEADINGS = {
    "compromise indicator": "Compromise indicators",
    "exposure": "Exposure",
    "hygiene": "Hygiene",
}


def _print_assessment(assessment: dict, args: argparse.Namespace) -> None:
    findings = assessment["findings"]
    print(f"Host       {assessment['host']}")
    print(f"Bundle     {assessment['bundle_id']}")
    print(
        f"Baseline   {assessment['baseline_id']}"
        + (" (set just now)" if assessment["baseline_set_now"] else "")
    )
    for note in assessment["notes"]:
        print(f"Note       {note}")
    scored = assessment.get("score")
    if scored:
        print(
            f"Score      {percent(scored['probability'])} probability of compromise:"
            f" {scored['band']} (prior {percent(scored['prior'])}, {scored['prior_source']})"
        )
        for c in scored["contributors"][:5]:
            capped = f", capped ({c['capped']})" if c["capped"] else ""
            print(f"           {percent(c['share']):>4}  {c['title']} (×{c['ratio']:g}{capped})")
        rest = len(scored["contributors"]) - 5
        if rest > 0:
            print(f"           and {rest} more")
        rating = scored["hygiene_and_exposure"]
        print(f"Hygiene    rated separately: {rating['band']}")
    suppressed = [f for f in findings if f.get("suppressed_by")]
    findings = [f for f in findings if not f.get("suppressed_by")]
    applied = assessment.get("whitelist")
    if applied:
        expired = f", {len(applied['expired'])} expired" if applied["expired"] else ""
        print(
            f"Whitelist  {len(applied['rules'])} rule(s){expired}; {len(suppressed)} finding(s)"
            " suppressed"
            + (" (--suppressed lists them)" if suppressed and not args.suppressed else "")
        )
    by_band = {band: sum(f["band"] == band for f in findings) for band in BANDS}
    print("Findings   " + ", ".join(f"{n} {band}" for band, n in by_band.items()))
    for category in CATEGORIES:
        shown = [
            f for f in findings if f["category"] == category and (args.info or f["band"] != "info")
        ]
        if not shown:
            continue
        print(f"\n{HEADINGS[category]}:")
        for f in shown:
            marks = (" [new]" if f["new"] else "") + (" [uncertain]" if f["uncertain"] else "")
            print(f"  {f['band'].upper():8} {f['title']}{marks}")
            print(f"           {f['summary'][:200]}")
            if f["uncertain"]:
                print(f"           uncertain: {f['uncertain'][:200]}")
    hidden = sum(f["band"] == "info" for f in findings)
    if hidden and not args.info:
        print(f"\n({hidden} informational findings: --info lists them)")
    if suppressed and args.suppressed:
        print("\nSuppressed by the whitelist:")
        for f in suppressed:
            rule = f["suppressed_by"]
            print(f"  {f['band'].upper():8} {f['title']}")
            print(f"           {f['summary'][:200]}")
            print(f"           by {rule['layer']} / {rule['rule']}: {rule['reason'][:150]}")
    coverage = assessment["coverage"]
    print("\nCoverage:")
    for name, reach in coverage["log_reach"].items():
        print(f"  {name:15} {reach['from'][:16]} to {reach['to'][:16]} ({reach['days']} days)")
    for gap in coverage["gaps"]:
        print(f"  gap: {gap[:200]}")
    for c in assessment["checks"]:
        if c["status"].startswith("failed"):
            print(f"  check {c['check']} {c['status']}")
    waiting: dict[str, list[str]] = {}
    for c in assessment["checks"]:
        if c["status"] not in ("ran",) and not c["status"].startswith("failed"):
            waiting.setdefault(c["status"], []).append(c["check"])
    for why, names in waiting.items():
        print(f"  not run ({why}): {', '.join(names)}")


def _brief(item: dict) -> str:
    text = " ".join(f"{k}={v}" for k, v in item.items() if v not in (None, "", [], {}))
    return text if len(text) <= 100 else text[:99] + "…"


def cmd_changes(args: argparse.Namespace) -> int:
    """What changed on a host: its latest (or a given) bundle's snapshot
    against the previous bundle's and the baseline's."""
    base = home()
    store = Store(database_file(base))
    try:
        found = changes(
            store,
            args.host,
            _identity(args, base),
            load_config(base).recipients,
            args.bundle,
        )
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"Host       {found.host}")
    print(f"Bundle     {found.bundle_id}")
    if found.baseline_set_now:
        print(
            f"Baseline   {found.baseline_id}: set just now, at the host's first analysis;"
            " change-based checks start from it"
        )
    else:
        print(f"Baseline   {found.baseline_id}")
    for note in found.notes:
        print(f"Note       {note}")
    if not found.comparisons:
        print("Nothing else to compare with.")
    for comparison in found.comparisons:
        if comparison.newer:
            print(
                f"\nFrom this bundle to the {comparison.label} bundle, {comparison.bundle_id},"
                " which is newer:"
            )
        else:
            print(f"\nSince the {comparison.label} bundle, {comparison.bundle_id}:")
        if not comparison.differences:
            print("  no changes")
        for name, diff in comparison.differences.items():
            counts = ", ".join(
                f"{len(diff[k])} {k}" for k in ("added", "removed", "changed") if diff[k]
            )
            print(f"  {name}: {counts or 'no changes'}")
            for note in diff["notes"]:
                print(f"    not comparable: {note}")
            limit = None if args.all else SHOWN
            for mark, kind in (("+", "added"), ("-", "removed")):
                keys = list(diff[kind])
                for key in keys[:limit]:
                    print(f"    {mark} {key}  {_brief(diff[kind][key])}".rstrip())
                if limit is not None and len(keys) > limit:
                    print(f"    … {len(keys) - limit} more {kind} (--all lists them)")
            keys = list(diff["changed"])
            for key in keys[:limit]:
                fields = "; ".join(
                    f"{f}: {old} → {new}" for f, (old, new) in diff["changed"][key].items()
                )
                print(f"    ~ {key}  {fields[:200]}")
            if limit is not None and len(keys) > limit:
                print(f"    … {len(keys) - limit} more changed (--all lists them)")
    return 0


def cmd_baseline_show(args: argparse.Namespace) -> int:
    base = home()
    store = Store(database_file(base))
    try:
        rows = store.baselines(args.host)
        identity = (
            _identity(args, base) if args.identity or load_config(base).identity_file else None
        )
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    if not rows:
        print(f"No baseline for {args.host} yet: `checker changes {args.host}` sets the first.")
        return 0
    for row in rows:
        reason = open_text(row["reason"], identity) if identity and row["reason"] else None
        who = f"{row['operator']}@{row['controller']}"
        line = f"{row['at']}  {row['how']:11}  {row['bundle_id']}  by {who}"
        print(line + (f"  — {reason}" if reason else ""))
    return 0


def cmd_baseline_accept(args: argparse.Namespace) -> int:
    base = home()
    store = Store(database_file(base))
    try:
        row, notes = accept(
            store,
            args.host,
            args.reason,
            _identity(args, base),
            load_config(base).recipients,
            args.bundle,
        )
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"{args.host}: baseline is now {row['id']}; later changes are compared with it.")
    for note in notes:
        print(f"Note: {note}.")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    """Parse a bundle into events (or load its stored parse) and list them."""
    base = home()
    store = Store(database_file(base))
    try:
        row = store.bundle(args.bundle)
        identity = _identity(args, base)
        parsed = None if args.reparse else load_events(store, row, identity)
        if parsed is None:
            parsed = parse_bundle(row, identity)
            store_parsed(store, row, load_config(base).recipients, parsed)
        else:
            store.custody(row["id"], "viewed", {"events": True})
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    summary = parsed.summary
    offset = summary.get("clock_offset_seconds")
    zone = summary.get("time_zone")
    assumed = " (assumed)" if summary.get("time_zone_assumed") else ""
    print(f"Bundle     {row['id']}")
    print(
        f"Events     {summary.get('events')} ({summary.get('own_session')} from this tool's"
        " own session, shown with --own)"
    )
    print(
        f"Clock      offset {offset if offset is not None else 'unknown'} s; zone {zone}{assumed}"
    )
    if summary.get("problem"):
        print(f"Problem    {summary['problem']}")
    if summary.get("own_login_found") is False:
        print(
            "Note       this tool's own SSH login was not found in the logs, so it and what"
            " followed from it are listed as findings (a NAT between the controller and"
            " the host changes the source port it is recognised by)"
        )
    for event in parsed.events:
        if event.own_session and not args.own:
            continue
        if args.type and not event.type.startswith(args.type):
            continue
        detail = " ".join(f"{k}={v}" for k, v in event.fields.items())
        own = " [own session]" if event.own_session else ""
        print(f"{event.corrected or '-':32} {event.type:26} {detail}{own}")
    return 0


def _expired_notice(base: Path) -> None:
    """One line when stored evidence is past its retention period (policy
    §8), so it isn't kept longer without anyone knowing. Never fails the
    command it follows."""
    try:
        config = load_config(base)
        store = Store(database_file(base))
        try:
            count = expired_count(
                store, base, {h.name for h in load_inventory().hosts}, config.retention_days
            )
        finally:
            store.close()
    except Exception:  # noqa: BLE001 - a reminder must never break collect or analyze
        return
    if count:
        print(
            f"Note: {count} bundle(s) are older than the {config.retention_days}-day retention"
            " period: `checker purge --expired` deletes them."
        )


def cmd_purge(args: argparse.Namespace, ask: Callable[[str], str] = input) -> int:
    """Delete stored evidence (policy §8), after showing what goes."""
    base = home()
    try:
        config = load_config(base)
        before = parse_before(args.before) if args.before else None
        inventory = {h.name for h in load_inventory().hosts}
    except (EvidenceError, ValueError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    store = Store(database_file(base))
    try:
        try:
            chosen = purge_plan(
                store, base, inventory, config.retention_days, args.host, before, args.expired
            )
        except ValueError as exc:
            print(f"checker: {exc}", file=sys.stderr)
            return 2
        if args.expired and not inventory:
            # Expiry keeps inventoried hosts' baselines: with no inventory (a
            # lost or moved hosts file) it would take every one.
            print(
                f"checker: --expired needs the inventory ({hosts_file()} is missing or empty), or"
                " it would purge every host's baseline; purge a removed host by name instead",
                file=sys.stderr,
            )
            return 2
        if args.host and not store.bundles(args.host):
            print(f"checker: no stored bundles for {args.host}", file=sys.stderr)
            return 2
        for row in chosen.kept:
            print(
                f"Kept: {row['id']}, {row['host']}'s current baseline (older than the retention"
                " period; it goes when a newer baseline is accepted)."
            )
        if chosen.outside:
            print(
                "checker: these bundles are stored outside this home's evidence folder, so"
                " nothing was purged: " + ", ".join(chosen.outside),
                file=sys.stderr,
            )
            return 1
        left = leftovers(store, base)
        if not chosen.bundles and not left:
            print("Nothing to purge.")
            return 0
        if left:
            print(f"{len(left)} file(s) an earlier purge couldn't delete will be deleted too.")
        if chosen.bundles:
            print(f"To purge: {len(chosen.bundles)} bundle(s), with their events, snapshots,")
            print(
                f"assessments and custody records; {len(chosen.files)} file(s) and"
                f" {len(chosen.reports)} report(s)."
            )
        for row in chosen.bundles:
            print(f"  {row['started_at']}  {row['host']:20} {row['id']}")
        for host, what in sorted(chosen.baselines.items()):
            if what == "moved":
                print(
                    f"Warning: {host}'s baseline goes too. Its next analysis takes its oldest"
                    " remaining bundle as the baseline, and changes made before that bundle"
                    " (accepted or not) will no longer show."
                )
        if args.dry_run:
            print("Dry run: nothing deleted.")
            return 0
        if not args.yes and ask("Delete these permanently? Type 'purge' to go on: ") != "purge":
            print("Nothing deleted.")
            return 1
        outcome = execute(store, base, chosen)
    except (EvidenceError, OSError, sqlite3.Error) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"Purged {outcome.counts['bundles']} bundle(s); {len(outcome.deleted)} file(s) deleted.")
    for path, reason in outcome.failed:
        print(
            f"checker: couldn't delete {path} ({reason}); the next purge tries again",
            file=sys.stderr,
        )
    return 1 if outcome.failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        print(f"checker {__version__}")
        parser.print_help()
        return 0
    return handler(args)

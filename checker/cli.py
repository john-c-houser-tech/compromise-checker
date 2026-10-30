"""The `checker` command. Subcommands arrive with the features they drive."""

import argparse
import asyncio
import json
import sqlite3
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

import pyrage
from pydantic import ValidationError

from checker import __version__
from checker.advisor.keys import (
    KeySourceError,
    key_places,
    looks_like_anthropic_key,
    read_api_key,
)
from checker.analysis import load_events, parse_bundle, store_parsed
from checker.assess import analyze, prior_for
from checker.baseline import accept, changes, usable_bundles
from checker.checks import BANDS, CATEGORIES
from checker.collect import collect_hosts
from checker.credentials import password_for
from checker.evidence import (
    Advisor,
    EvidenceError,
    Store,
    check_sidecar,
    config_file,
    database_file,
    file_sha256,
    initialise,
    judge,
    load_config,
    load_identity,
    mail_fingerprint,
    mail_key,
    mail_key_file,
    open_bundle,
    open_text,
)
from checker.inventory import Host, home, hosts_file, inventory_transaction, load_inventory
from checker.purge import execute, expired_count, leftovers, parse_before
from checker.purge import plan as purge_plan
from checker.report import write_report
from checker.scoring import percent
from checker.settings import (
    EXEC_RECORDS,
    HOME_TEXT,
    SETTABLE,
    advisor_question,
    describe,
    key_source_words,
    recipient,
    recipients,
    value_of,
)
from checker.settings import change as change_setting
from checker.settings import message as setting_message
from checker.transport import TransportError, fetch_host_key, trust_host_key
from checker.whitelist import WhitelistError, check_all
from checker.whitelist import for_host as whitelist_for_host
from checker.whitelist import load_with as whitelist_load_with
from checker.whitelist import other_sets as whitelist_other_sets
from checker.whitelist_review import compare as whitelist_compare
from checker.whitelist_review import stale as whitelist_stale


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


def _advisor_choice(args: argparse.Namespace, ask: Callable[[str], str] | None) -> bool:
    """The advisor is an explicit choice (DESIGN.md §3.5): --advisor on|off,
    else asked when someone is there to answer, else off."""
    if args.advisor is not None:
        return args.advisor == "on"
    if ask is None:
        if not sys.stdin.isatty():
            return False
        ask = input
    print(advisor_question(args.advisor_redaction))
    try:
        answer = ask("Turn the AI advisor on? [y/N] ")
    except EOFError:
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def cmd_init(args: argparse.Namespace, ask: Callable[[str], str] | None = None) -> int:
    base = home()
    if config_file(base).exists():  # before asking anything
        print(f"checker: already set up ({config_file(base)}); nothing changed", file=sys.stderr)
        return 1
    try:
        advisor = Advisor(api_key_source=args.advisor_key_source, redaction=args.advisor_redaction)
    except ValidationError as exc:
        print(f"checker: {setting_message(exc, '--advisor-key-source')}", file=sys.stderr)
        return 2
    advisor.enabled = _advisor_choice(args, ask)
    try:
        config, identity_path = initialise(
            base,
            args.recipient,
            args.home_text,
            args.web_access_logs,
            args.exec_records,
            advisor,
        )
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
    for line in describe(config):
        print(line)
    print(f"Mail logs' addresses are fingerprinted with the mail key in {mail_key_file(base)};")
    print("keep it as private as the evidence key.")
    print("Change any of these later with `checker config set`.")
    print("Next: `checker hosts add`, then `checker trust`, then `checker collect`.")
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    try:
        config = load_config(home())
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    for line in describe(config):
        print(line)
    print(f"Retention: {config.retention_days} days. Prior: {percent(config.prior)}.")
    print("Settable with `checker config set KEY VALUE`:")
    for key, setting in SETTABLE.items():
        print(f"  {key} = {json.dumps(value_of(config, key))}    ({setting.help})")
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    try:
        old, new, config = change_setting(home(), args.key, args.value)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error) as exc:
        print(f"checker: {args.key} not changed: {exc}", file=sys.stderr)
        return 1
    if old == new:
        print(f"{args.key} is already {json.dumps(new)}. Nothing changed.")
        return 0
    print(f"{args.key}: {json.dumps(old)} -> {json.dumps(new)} (recorded).")
    if args.key == "advisor.enabled" and new:
        advisor = config.advisor
        print(advisor_question(advisor.redaction, recipients(advisor)))
    for line in describe(config):
        print(line)
    return 0


def cmd_config_history(args: argparse.Namespace) -> int:
    base = home()
    if not database_file(base).exists():
        print("checker: not set up yet: run `checker init`", file=sys.stderr)
        return 2
    store = Store(database_file(base))
    try:
        rows = store.config_changes()
    finally:
        store.close()
    if not rows:
        print("No settings changed since `checker init`.")
    for row in rows:
        print(
            f"{row['at']}  {row['operator']}@{row['controller']}  {row['setting']}:"
            f" {row['old']} -> {row['new']}"
        )
    return 0


def cmd_config_check_key(args: argparse.Namespace) -> int:
    """Read the advisor's API key from its source, as `checker advise` will,
    and say whether that worked. Sends nothing; never shows the key."""
    try:
        advisor = load_config(home()).advisor
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    sources = [("", advisor.api_key_source, advisor.api, key_places(advisor.api, advisor.base_url))]
    if advisor.fallback == "model":
        fallback = advisor.fallback_model
        sources.append(
            ("The fallback model's key: ", fallback.api_key_source, fallback.api,
             key_places(fallback.api, fallback.base_url, fallback=True))
        )  # fmt: skip
    for label, source, api, places in sources:
        if source == "none":
            print(f"{label}No key is used (api_key_source none). Nothing was sent.")
            continue
        print(f"{label}Reading the key from {key_source_words(source, places)}…")
        try:
            key = read_api_key(source, places)
        except KeySourceError as exc:
            print(f"checker: {exc}", file=sys.stderr)
            return 1
        print(f"A key was read ({len(key or '')} characters). Nothing was sent.")
        if api == "anthropic" and not label and not advisor.base_url:
            if not looks_like_anthropic_key(key or ""):
                print("It doesn't look like an Anthropic API key (they start with sk-ant-).")
    if not advisor.enabled:
        print("The advisor is off: `checker config set advisor.enabled on` to use it.")
    return 0


def cmd_mail_hash(args: argparse.Namespace) -> int:
    """How known addresses appear in collected mail logs (policy §7)."""
    base = home()
    try:
        load_config(base)
        key = mail_key(base)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    status = 0
    for address in args.addresses:
        try:
            print(f"{address}\t{mail_fingerprint(key, address)}")
        except ValueError as exc:
            print(f"checker: {exc}", file=sys.stderr)
            status = 2
    return status


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
    if merged is None or not (merged.rules or merged.windows):
        print(f"No whitelist rules or maintenance windows apply to {args.host}.")
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
    for placed in merged.windows:
        window = placed.rule
        expired = window.expires != "never" and window.expires < today
        when = (
            f"every {','.join(window.every)} {window.start_time}-{window.end_time}"
            f" {window.tz or 'UTC'}"
            if window.every
            else f"{window.start.isoformat()} to {window.end.isoformat()}"
        )
        print(
            f"{placed.layer:20} {window.id:30} maintenance {when}"
            + (f" EXPIRED {window.expires}" if expired else f" until {window.expires}")
        )
        print(f"{'':20} {window.reason}  ({window.owner})")
    for item in merged.disabled:
        print(f"{item['by']:20} switched off {item['id']}: {item['reason']}  ({item['owner']})")
    return 0


def cmd_whitelist_test(args: argparse.Namespace) -> int:
    """A proposed file against the host's stored analyses in the retention
    period: the score before and after, and what it would hide or reveal.
    Nothing is saved."""
    base = home()
    store = Store(database_file(base))
    try:
        config = load_config(base)
        identity = _identity(args, base)
        inventory = _inventory_for_priors()
        entry = next((h for h in inventory.hosts if h.name == args.host), None)
        group = entry.group if entry else None
        try:
            current = _whitelist_for(base, args.host, inventory)
        except EvidenceError as exc:
            # Testing the fix for a broken file must still work.
            print(f"Note: the current set is invalid ({exc}); comparing with no whitelist.")
            current = None
        try:
            proposed = whitelist_load_with(base, args.host, group, args.layer, Path(args.file))
        except WhitelistError as exc:
            raise EvidenceError(f"the proposed file: {exc}") from None
        since = datetime.now(UTC) - timedelta(days=config.retention_days)
        results = whitelist_compare(store, args.host, identity, current, proposed, since)
    except (pyrage.DecryptError, OSError) as exc:
        print(f"checker: can't read the stored analyses: {exc}", file=sys.stderr)
        return 1
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    if not results:
        print(f"No scored analyses of {args.host} in the last {config.retention_days} days.")
        return 0
    changed = 0
    for r in results:
        if r.get("skipped"):
            print(f"{r['bundle']}  skipped: {r['skipped']} (run checker analyze first)")
            continue
        (p0, b0), (p1, b1) = r["before"], r["after"]
        moved = r["hidden"] or r["revealed"] or r["rebanded"]
        changed += bool(moved)
        print(f"{r['bundle']}  {percent(p0)} {b0} -> {percent(p1)} {b1}")
        for line in r["hidden"]:
            print(f"  would hide     {line}")
        for line in r["revealed"]:
            print(f"  would reveal   {line}")
        for line in r["rebanded"]:
            print(f"  would reband   {line}")
    compared = sum(1 for r in results if not r.get("skipped"))
    print(f"{changed} of {compared} analyses would change. Nothing was saved.")
    return 0


def _days(text: str) -> int:
    try:
        days = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number of days") from None
    if not 1 <= days <= 36500:
        raise argparse.ArgumentTypeError("between 1 and 36500")
    return days


def cmd_whitelist_stale(args: argparse.Namespace) -> int:
    """Rules no recent analysis needed, and rules expired or expiring."""
    base = home()
    store = Store(database_file(base))
    try:
        identity = _identity(args, base)
        inventory = _inventory_for_priors()
        sets = {h.name: _whitelist_for(base, h.name, inventory) for h in inventory.hosts}
        sets |= whitelist_other_sets(base, inventory)
        found = whitelist_stale(store, identity, sets, args.days)
    except (pyrage.DecryptError, OSError) as exc:
        print(f"checker: can't read the stored analyses: {exc}", file=sys.stderr)
        return 1
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    headings = {
        "stale": f"No match in the last {args.days} days",
        "expired": "Expired (no longer applied)",
        "expiring": "Expiring within 30 days",
    }
    for kind, heading in headings.items():
        print(f"{heading}:")
        for line in found[kind] or ["none"]:
            print(f"  {line}")
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
    init.add_argument(
        "--web-access-logs",
        action="store_true",
        help=(
            "also collect web servers' access logs (visitors' requests), masked; error"
            " logs are always collected"
        ),
    )
    init.add_argument(
        "--exec-records",
        choices=sorted(EXEC_RECORDS),
        default="web",
        help=(
            "whose program starts to collect from the audit log: web (the web server's"
            " accounts, the default), privileged (also root, service and administrator"
            " accounts) or all"
        ),
    )
    init.add_argument(
        "--advisor",
        choices=["on", "off"],
        help=(
            "turn the optional AI advisor on or off (policy §9); without it, `init` asks"
            " when run in a terminal, and leaves it off otherwise"
        ),
    )
    init.add_argument(
        "--advisor-key-source",
        default="env",
        metavar="SOURCE",
        help=(
            "where the advisor's API key comes from: env (ANTHROPIC_API_KEY, the default),"
            " keyring, or command:<command> that prints it"
        ),
    )
    init.add_argument(
        "--advisor-redaction",
        choices=["pseudonymize", "strict", "none"],
        default="pseudonymize",
        help="what the advisor's requests may contain (default pseudonymize)",
    )
    init.set_defaults(handler=cmd_init)

    configuring = commands.add_parser("config", help="show or change settings after init")
    config_commands = configuring.add_subparsers(
        dest="config_command", metavar="ACTION", required=True
    )
    config_commands.add_parser("show", help="the settings, in words").set_defaults(
        handler=cmd_config_show
    )
    setting = config_commands.add_parser(
        "set",
        help="change a setting (recorded)",
        description=(
            "Change one setting, validated and recorded. config.yaml is written back"
            " whole, so comments added to it by hand are lost. A value starting with"
            " '-' goes after '--': checker config set KEY -- VALUE."
        ),
    )
    setting.add_argument("key", choices=list(SETTABLE), metavar="KEY", help=", ".join(SETTABLE))
    setting.add_argument("value")
    setting.set_defaults(handler=cmd_config_set)
    config_commands.add_parser(
        "history", help="every setting changed since init: who, when, old and new"
    ).set_defaults(handler=cmd_config_history)
    config_commands.add_parser(
        "check-key", help="read the advisor's API key from its source (sends nothing)"
    ).set_defaults(handler=cmd_config_check_key)

    collect = commands.add_parser("collect", help="collect evidence from hosts")
    which = collect.add_mutually_exclusive_group(required=True)
    which.add_argument("names", nargs="*", default=[], help="host names")
    which.add_argument("--group", help="every host in this group")
    which.add_argument("--all", action="store_true", help="every host in the inventory")
    collect.add_argument("--days", type=int, default=30, help="look-back window (default 30)")
    collect.add_argument("--parallel", type=int, default=5, help="hosts at a time (default 5)")
    collect.set_defaults(handler=cmd_collect)

    hashing = commands.add_parser(
        "mail-hash", help="show how known email addresses appear in collected mail logs"
    )
    hashing.add_argument("addresses", nargs="+", help="email addresses (or bare local names)")
    hashing.set_defaults(handler=cmd_mail_hash)

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
    chosen.add_argument(
        "--open",
        nargs="?",
        const="",
        metavar="FILE",
        help="show a report in the browser (default: the newest), served from memory",
    )
    reporting.add_argument("--bundle", help="this bundle rather than the host's latest")
    reporting.add_argument(
        "--output", help="the file to write (default: reports/ in the home; ends in .age)"
    )
    reporting.add_argument(
        "--plain", action="store_true", help="write plain HTML, not encrypted (to hand it on)"
    )
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
    packing = commands.add_parser("packs", help="threat packs (DESIGN.md §10)")
    pack_commands = packing.add_subparsers(dest="packs_command", metavar="ACTION", required=True)
    checking_pack = pack_commands.add_parser(
        "check", help="validate a pack file, without trusting or adding it"
    )
    checking_pack.add_argument("file", help="the pack's YAML file")
    checking_pack.set_defaults(handler=cmd_packs_check)
    adding_pack = pack_commands.add_parser(
        "add", help="check a pack's signature and content, and put it in force"
    )
    adding_pack.add_argument("file", help="the pack's YAML file")
    adding_pack.add_argument("--signature", help="its minisign signature (default: FILE.minisig)")
    adding_pack.set_defaults(handler=cmd_packs_add)
    listing_packs = pack_commands.add_parser("list", help="the packs in force, and retired ones")
    listing_packs.add_argument("--retired", action="store_true", help="also the retired ones")
    listing_packs.set_defaults(handler=cmd_packs_list)
    showing_pack = pack_commands.add_parser("show", help="what a pack in force says")
    showing_pack.add_argument("id", help="the pack's id")
    showing_pack.set_defaults(handler=cmd_packs_show)
    retiring_pack = pack_commands.add_parser("retire", help="take a pack out of use (it is kept)")
    retiring_pack.add_argument("id", help="the pack's id")
    retiring_pack.add_argument("--reason", required=True, help="why, for the record")
    retiring_pack.set_defaults(handler=cmd_packs_retire)
    keying = pack_commands.add_parser("keys", help="the keys trusted to sign packs")
    key_commands = keying.add_subparsers(dest="keys_command", metavar="ACTION")
    keying.set_defaults(handler=cmd_packs_keys)
    adding_keys = key_commands.add_parser(
        "add", help="put a newer NouriLoop key list in force (air-gapped sites)"
    )
    adding_keys.add_argument("file", help="keys.yaml")
    adding_keys.add_argument("--signature", help="its signature (default: FILE.minisig)")
    adding_keys.set_defaults(handler=cmd_packs_keys_add)
    trusting = pack_commands.add_parser("trust", help="your organization's own pack keys")
    trust_commands = trusting.add_subparsers(dest="trust_command", metavar="ACTION", required=True)
    trust_add = trust_commands.add_parser("add", help="trust a key for your private packs")
    trust_add.add_argument("name", help="a name for it")
    trust_add.add_argument("key", help="its minisign public key file (.pub)")
    trust_add.set_defaults(handler=cmd_packs_trust_add)
    trust_remove = trust_commands.add_parser(
        "remove", help="stop trusting a key; packs it signed are retired"
    )
    trust_remove.add_argument("name")
    trust_remove.set_defaults(handler=cmd_packs_trust_remove)

    whitelisting = commands.add_parser("whitelist", help="check the whitelist files")
    whitelist_commands = whitelisting.add_subparsers(
        dest="whitelist_command", metavar="ACTION", required=True
    )
    checking = whitelist_commands.add_parser(
        "check", help="validate every whitelist file; with a host, show its merged rules"
    )
    checking.add_argument("host", nargs="?")
    checking.set_defaults(handler=cmd_whitelist_check)
    testing = whitelist_commands.add_parser(
        "test", help="what a proposed whitelist file would hide or reveal, on stored analyses"
    )
    testing.add_argument("host")
    testing.add_argument("--file", required=True, help="the proposed file")
    testing.add_argument(
        "--as",
        dest="layer",
        choices=["host", "group", "global"],
        default="host",
        help="which of the host's files it would replace (default: the host's)",
    )
    testing.add_argument("--identity", help="the evidence private key file")
    testing.set_defaults(handler=cmd_whitelist_test)
    staling = whitelist_commands.add_parser(
        "stale", help="rules that matched nothing lately, and rules expired or expiring"
    )
    staling.add_argument(
        "--days", type=_days, default=90, help="how far back, 1 to 36500 (default 90)"
    )
    staling.add_argument("--identity", help="the evidence private key file")
    staling.set_defaults(handler=cmd_whitelist_stale)
    advising = commands.add_parser(
        "advise", help="ask the optional AI advisor about a host's latest analysis"
    )
    advising.add_argument("host", nargs="?")
    advising.add_argument(
        "--all",
        action="store_true",
        help=(
            "every host with a usable bundle, asking once for the whole run; explanations"
            " of quiet hosts use advisor.triage_model when it is set"
        ),
    )
    advising.add_argument(
        "--show",
        action="store_true",
        help="print the request exactly as it would be sent; send nothing",
    )
    advising.add_argument(
        "--role",
        choices=["explain", "whitelist", "coverage", "remediation"],
        default="explain",
        help=(
            "explain the analysis (default), propose whitelist rules for a person to review,"
            " suggest settings and host configuration for better coverage, or advise on"
            " remediation"
        ),
    )
    advising.add_argument(
        "--yes",
        action="store_true",
        help="send even above advisor.max_cost_per_run, without asking",
    )
    advising.add_argument(
        "--redaction",
        choices=["pseudonymize", "strict", "none"],
        help="preview another redaction mode than the configured one",
    )
    advising.add_argument("--bundle", help="a given bundle instead of the latest")
    advising.add_argument("--identity", help="the evidence private key file")
    advising.set_defaults(handler=cmd_advise)
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

    running = commands.add_parser(
        "run", help="collect, analyze, report and purge what has expired, in one pass"
    )
    chosen_hosts = running.add_mutually_exclusive_group(required=True)
    chosen_hosts.add_argument("names", nargs="*", default=[], help="host names")
    chosen_hosts.add_argument("--group", help="every host in this group")
    chosen_hosts.add_argument("--all", action="store_true", help="every host in the inventory")
    running.add_argument(
        "--unattended",
        action="store_true",
        help="ask nothing: refuse hosts that would need a prompt, before collecting",
    )
    running.add_argument("--days", type=int, default=30, help="look-back window (default 30)")
    running.add_argument("--parallel", type=int, default=5, help="hosts at a time (default 5)")
    running.add_argument("--identity", help="the evidence private key file")
    running.set_defaults(handler=cmd_run)

    scheduling = commands.add_parser("schedule", help="run `checker run --all` daily, on a timer")
    schedule_commands = scheduling.add_subparsers(
        dest="schedule_command", metavar="ACTION", required=True
    )
    install = schedule_commands.add_parser(
        "install", help="write and start the timer (systemd on Linux, launchd on macOS)"
    )
    install.add_argument("--at", default="03:00", help="time of day, HH:MM (default 03:00)")
    install.set_defaults(handler=cmd_schedule_install)
    schedule_commands.add_parser("remove", help="stop and delete the timer").set_defaults(
        handler=cmd_schedule_remove
    )
    schedule_commands.add_parser("show", help="whether the timer is installed").set_defaults(
        handler=cmd_schedule_show
    )
    return parser


SHOWN = 20  # items listed per kind and section without --all


def _advise_all(args, base, store, config, inventory, identity) -> int:
    """`checker advise --all`: every host's estimate first, one question for
    the whole run (against advisor.max_cost_per_run, as one run), then each
    request in turn. A host that can't be asked is said and skipped."""
    from checker.advisor.advise import _client, advise, plan
    from checker.advisor.client import AdvisorError

    advisor = config.advisor
    if not advisor.enabled:
        raise AdvisorError(
            "the advisor is off: `checker config set advisor.enabled on` turns it on"
        )
    hosts = [h for h in store.hosts() if usable_bundles(store, h)]
    if not hosts:
        raise EvidenceError("no host has a usable bundle yet: collect first")
    status, planned = 0, []
    for host in hosts:
        try:
            planned.append(
                plan(store, host, identity, config, inventory, prior_for(host, config, inventory),
                     _whitelist_for(base, host, inventory), args.role)
            )  # fmt: skip
        except KeyboardInterrupt:
            print("checker: interrupted while estimating; nothing was sent", file=sys.stderr)
            return 130
        except (EvidenceError, OSError, AdvisorError) as exc:
            print(f"checker: {host}: {exc}; skipped", file=sys.stderr)
            status = 1
        except Exception as exc:  # noqa: BLE001 - one host's trouble isn't the others'
            print(f"checker: {host}: {type(exc).__name__}: {exc}; skipped", file=sys.stderr)
            status = 1
    for item in planned:
        print(
            f"{item.host}: {item.line}"
            + (" (the triage model: a quiet host)" if item.triaged else "")
        )
    if not planned:
        return 1
    known = [item.priced for item in planned if item.priced is not None]
    likely, most = sum(p.likely for p in known), sum(p.most for p in known)
    unknown = len(known) < len(planned)
    total = (
        f"{len(planned)} requests: likely about ${likely:.2f} in all, at most about ${most:.2f}"
        + (", and some at a cost not known here" if unknown else "")
        + "."
    )
    print(total)
    if unknown or likely > advisor.max_cost_per_run:
        if not args.yes:
            if not sys.stdin.isatty():
                print("checker: not sent: confirm with --yes, or raise advisor.max_cost_per_run",
                      file=sys.stderr)  # fmt: skip
                return 1
            try:
                answer = input("Send them? [y/N] ")
            except KeyboardInterrupt:
                print("\nNothing was sent.")
                return 130
            except EOFError:
                print("\nNothing was sent.")
                return 1
            if answer.strip().lower() not in ("y", "yes"):
                print("Nothing was sent.")
                return 1
    # The key is read once, after the yes: one password manager prompt.
    try:
        client = _client(advisor.api_key_source, advisor.api, advisor.base_url)
    except KeyboardInterrupt:
        print("checker: interrupted reading the key; nothing was sent", file=sys.stderr)
        return 130
    clients: dict = {}  # the fallback model's, read once too if a host needs it
    for done, item in enumerate(planned):
        before = len(store.advice(item.bundle_id))
        try:
            print(f"\n== {item.host} ==")
            advice = advise(
                store, item.host, identity, config, inventory, item.prior, item.whitelist,
                role=args.role, client=client, say=lambda line: None, home=base,
                planned=item, clients=clients,
            )  # fmt: skip
            _print_advice(advice, args.role)
        except KeyboardInterrupt:
            left = len(store.advice(item.bundle_id)) > before
            print(
                f"checker: interrupted at {item.host} ({done} host(s) before it):"
                + (" its request may have been sent, and is recorded;" if left
                   else " its request was not sent;")
                + f" {len(planned) - done - 1} after it not sent",
                file=sys.stderr,
            )  # fmt: skip
            return 130
        except Exception as exc:  # noqa: BLE001 - one host's trouble isn't the others'
            print(f"checker: {item.host}: {type(exc).__name__}: {exc}", file=sys.stderr)
            status = 1
            continue
        if advice.status != "answered":
            status = 1
    return status


def _print_advice(advice, role: str) -> None:
    from checker.report import visible

    def shown(text) -> str:  # the provider's and the model's words, safe for a terminal
        return str(visible(text, 4000))

    outcome = advice.outcome
    if outcome is not None:
        line = f"Asked {shown(outcome.model_asked)}"
        if outcome.declined_by:
            line += f"; declined by {shown(', '.join(outcome.declined_by))}"
        if outcome.model_answered:
            line += f"; answered by {shown(outcome.model_answered)}"
        print(line + ".")
    if advice.note:
        print(shown(advice.note[0].upper() + advice.note[1:]) + ".")
    if advice.warning:
        print(f"Warning: {shown(advice.warning)}.")
    answer = advice.answer
    if not answer:
        return
    if role == "whitelist":
        _print_proposals(advice, shown)
        return
    if role == "coverage":
        _print_coverage(advice, shown)
        return
    if role == "remediation":
        _print_remediation(answer, shown)
        return

    print()
    print(f"Verdict: {shown(answer['verdict'])}")
    print(shown(answer["summary"]))
    if answer["most_important"]:
        print("\nMost important:")
        for point in answer["most_important"]:
            print(f"  {shown(point['finding'])}: {shown(point['why'])}")
    if answer["innocent_explanations"]:
        print("\nPossible innocent explanations:")
        for item in answer["innocent_explanations"]:
            print(f"  {shown(item['finding'])}: {shown(item['explanation'])}")
    if answer["what_would_settle_it"]:
        print("\nWhat would settle it:")
        for question in answer["what_would_settle_it"]:
            print(f"  - {shown(question)}")
    print("\n(AI advice: the score is the tool's own and is unchanged. Stored, encrypted.)")


def _print_remediation(answer, shown) -> None:
    print()
    print(f"Urgency: {shown(answer['urgency'])}")
    print(shown(answer["summary"]))
    for title, key in (
        ("Preserve evidence first", "preserve"),
        ("Contain", "contain"),
        ("Eradicate", "eradicate"),
        ("Recover", "recover"),
    ):
        if answer.get(key):
            print(f"\n{title}:")
            for n, step in enumerate(answer[key], 1):
                mark = " [destroys state]" if step.get("destructive") else ""
                cites = ", ".join(step.get("findings") or [])
                print(
                    f"  {n}. {shown(step['action'])}{mark}"
                    + (f" ({shown(cites)})" if cites else "")
                )
                print(f"     Why: {shown(step['why'])}  Risk: {shown(step['risk'])}")
    if answer.get("tell"):
        print("\nTell:")
        for notify in answer["tell"]:
            print(f"  {shown(notify['role'])}: {shown(notify['what'])} ({shown(notify['when'])})")
    print("\n(AI advice for a person to weigh: nothing was run. Commands are text.)")


def _print_coverage(advice, shown) -> None:
    judged = advice.judged or []
    print()
    if not judged:
        print("No suggestions: coverage looks good to the advisor.")
    for item in judged:
        s = item.suggestion
        what = s.get("setting") if s.get("kind") == "setting" else s.get("item")
        if item.accepted:
            print(f"Suggested: {shown(s.get('why'))}")
            for cited in item.cited:
                print(f"  For {shown(cited)}")
            print(f"  Cost, as the advisor sees it: {shown(s.get('trade_off'))}")
            if item.note:
                print(f"  {item.note}")
            print(f"  {item.action}")  # the tool's own text, printed as it is
        else:
            print(f"Set aside: {shown(what)}: {shown(item.reason)}")
    if any(j.accepted for j in judged):
        print("\n(Suggestions only: nothing was changed. Settings take effect at the next")
        print("collection; host configuration is for an administrator to apply.)")


def _print_proposals(advice, shown) -> None:
    judged = advice.judged or []
    accepted = [j for j in judged if j.accepted]
    print()
    if not judged:
        print("No whitelist rules proposed.")
    for item in judged:
        name = shown(item.proposal.get("id"))
        if item.accepted:
            print(
                f"Proposed: {name}: hides {shown(', '.join(h.split(':')[0] for h in item.hides))}"
            )
        else:
            print(f"Set aside: {name}: {shown(item.reason)}")
    for point in advice.answer.get("left_alone") or []:
        print(f"Left alone: {shown(point['finding'])}: {shown(point['why'])}")
    if advice.file:
        print(f"\n{len(accepted)} rule(s) written to {advice.file}: nothing is in effect until")
        print("a person reviews them, sets each owner and copies them into the whitelist.")


def cmd_advise(args: argparse.Namespace) -> int:
    """The advisor's answer about a host's latest assessment (sent), or the
    request exactly as it would be sent (--show, sends nothing)."""
    from checker.advisor.advise import advise
    from checker.advisor.case import case_for_host, redact
    from checker.advisor.client import AdvisorError, build_request
    from checker.advisor.prices import tokens_in

    if args.all == bool(args.host):
        print("checker: name a host, or --all", file=sys.stderr)
        return 2
    if args.all and (args.show or args.bundle or args.redaction):
        print("checker: --show, --bundle and --redaction are for one host", file=sys.stderr)
        return 2
    base = home()
    store = Store(database_file(base))

    def requests_recorded() -> int:
        return sum(len(store.advice_for_host(h)) for h in store.hosts())

    recorded_before = requests_recorded()
    try:
        config = load_config(base)
        inventory = _inventory_for_priors()
        if args.all:
            prior = whitelist = None
        else:
            prior = prior_for(args.host, config, inventory)
            whitelist = _whitelist_for(base, args.host, inventory)
        identity = _identity(args, base)
        if args.all:
            return _advise_all(args, base, store, config, inventory, identity)
        if args.show:
            built, known, _ = case_for_host(
                store, args.host, identity, config.recipients, inventory, prior, whitelist,
                args.bundle,
            )  # fmt: skip
            mode = args.redaction or config.advisor.redaction
            payload, pseudonyms = redact(built, mode, known)
            request = build_request(payload, args.role, config.advisor)
            text = json.dumps(request.shown(), indent=1, ensure_ascii=False)
            print(text)
            placeholders = len(pseudonyms.originals) if pseudonyms else 0
            print(
                f"[{len(text)} characters, at most about {tokens_in(text)} tokens;"
                f" redaction {mode};"
                f" {placeholders} placeholders, kept only for this run. Nothing was sent.]",
                file=sys.stderr,
            )
            if mode != config.advisor.redaction:
                print(
                    f"[The configured redaction is {config.advisor.redaction};"
                    f" this preview used {mode}.]",
                    file=sys.stderr,
                )
            if config.advisor.fallback == "model":
                fallback = config.advisor.fallback_model
                print(
                    f"[If the model declines, the same case goes to {fallback.model},"
                    f" {recipient(fallback.api, fallback.base_url)}.]",
                    file=sys.stderr,
                )
            if not config.advisor.enabled:
                print("[The advisor is off; this is what it would send.]", file=sys.stderr)
            return 0
        if args.redaction:
            raise EvidenceError("--redaction only previews (with --show); set advisor.redaction")

        def confirm(question: str) -> bool:
            if args.yes:
                return True
            if not sys.stdin.isatty():
                print("checker: not sent: confirm with --yes, or raise advisor.max_cost_per_run",
                      file=sys.stderr)  # fmt: skip
                return False
            try:
                return input(question).strip().lower() in ("y", "yes")
            except (KeyboardInterrupt, EOFError):
                print()
                return False

        advice = advise(
            store, args.host, identity, config, inventory, prior, whitelist,
            role=args.role, bundle_id=args.bundle, confirm=confirm, home=base,
        )  # fmt: skip
    except (EvidenceError, OSError, AdvisorError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        sent = requests_recorded() > recorded_before
        print(
            "checker: interrupted; "
            + ("the request may have been sent, and is recorded" if sent else "nothing was sent"),
            file=sys.stderr,
        )
        return 130
    finally:
        store.close()
    _print_advice(advice, args.role)
    return 0 if advice.status == "answered" else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Write the HTML report: owner-only, encrypted unless --plain,
    confidential (policy §8); or, with --open, show one."""
    base = home()
    if args.open is not None:
        return _open_report(args, base)
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
        config = load_config(base)
        path = write_report(
            store,
            hosts,
            _identity(args, base),
            config.recipients,
            base / "reports",
            args.bundle,
            Path(args.output) if args.output else None,
            partial(prior_for, config=config, inventory=inventory),
            whitelists.get,
            config.advisor.enabled,
            args.plain,
        )
    except (EvidenceError, OSError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"Report written to {path}")
    if args.plain:
        print(
            "Warning: it is plain HTML, not encrypted, and confidential: it describes weaknesses"
            " an attacker could use. Keep it out of backups and synced folders, and delete it"
            " when it has been read."
        )
    else:
        print(f"Encrypted to the evidence key. To read it: checker report --open {path}")
    return 0


def _open_report(args: argparse.Namespace, base: Path) -> int:
    from checker.report import latest_report, view

    clashing = [f for f, given in (("--plain", args.plain), ("--output", args.output),
                                   ("--bundle", args.bundle)) if given]  # fmt: skip
    if clashing:
        print(f"checker: --open shows a report; {', '.join(clashing)} write one", file=sys.stderr)
        return 2
    try:
        path = Path(args.open) if args.open else latest_report(base / "reports")
        if path is None:
            raise EvidenceError("no report yet: `checker report HOST` writes one")
        if not path.name.endswith((".html", ".html.age")):
            raise EvidenceError(f"not a report (its name ends in .html.age or .html): {path}")
        if not path.is_file():
            raise EvidenceError(
                f"no such report: {path} (to write one for a host: checker report HOST)"
            )
        view(path, _identity(args, base) if path.suffix == ".age" else None)
    except (EvidenceError, OSError, UnicodeDecodeError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    print("Stopped.")
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
        if applied.get("maintenance"):
            print(
                f"           {applied['maintenance']} reboot(s) in maintenance windows,"
                " lowered (unexplained to info, unclean one step)"
            )
    order = {band: i for i, band in enumerate(BANDS)}
    findings = sorted(findings, key=lambda f: order[f["band"]])  # a window moves a band
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
            if f.get("maintenance"):
                m = f["maintenance"]
                marks += f" [maintenance {m['window']}, was {m['band']}]"
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
                f"assessments and custody records; {len(chosen.files)} file(s),"
                f" {len(chosen.reports)} report(s) and {len(chosen.proposals)} whitelist"
                " proposal file(s)."
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
    for path in outcome.changed:
        print(
            f"checker: {path} changed after the purge was planned, so it was left as it is;"
            " delete it yourself if it shows the purged evidence",
            file=sys.stderr,
        )
    return 1 if outcome.failed else 0


def _read_untrusted(name: str, limit: int) -> bytes:
    """A file someone else wrote: only a regular file, no more than `limit`
    bytes (one byte more, so "too large" can be told)."""
    import os
    import stat

    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(0, "not a regular file")
        return handle.read(limit + 1)


def cmd_packs_check(args: argparse.Namespace) -> int:
    """Validate a pack as the tool would read it: its format, then that
    its detections name checks this version of the tool has. The file is
    untrusted: only a regular file is read, no more than a pack may hold,
    and its text is shown with hidden characters escaped."""
    from checker.checks import load_checks
    from checker.packs.format import MAX_BYTES, PackError, read
    from checker.report import visible

    try:
        data = _read_untrusted(args.file, MAX_BYTES)
    except OSError as exc:
        print(f"checker: {args.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    try:
        pack = read(data)
    except PackError as exc:
        print(f"checker: {args.file} isn't a valid pack:", file=sys.stderr)
        for line in str(exc).splitlines():
            print(f"  {visible(line, 1000)}", file=sys.stderr)
        return 1
    known = load_checks()
    unknown = [d.check for d in pack.detections if d.check not in known]
    if unknown:
        print(
            f"checker: {args.file}: detections name checks this version doesn't have: "
            + ", ".join(unknown),
            file=sys.stderr,
        )
        return 1
    releases = ", ".join(dict.fromkeys(p.release for p in pack.exposure.packages))
    print(f"Valid: {pack.id} version {pack.version} ({visible(pack.title, 200)}), for {releases}.")
    print("Checked only: nothing was trusted or added (adding a pack checks its signature).")
    return 0


def _packs_lock(base: Path):
    from checker.files import locked

    return locked(base / "packs" / "state")


def cmd_packs_add(args: argparse.Namespace) -> int:
    from checker.checks import load_checks
    from checker.packs.format import MAX_BYTES
    from checker.packs.signing import MAX_SIGNATURE_BYTES
    from checker.packs.store import StoreError, add
    from checker.report import visible

    base = home()
    try:
        config = load_config(base)
        data = _read_untrusted(args.file, MAX_BYTES)
        signature = _read_untrusted(args.signature or f"{args.file}.minisig", MAX_SIGNATURE_BYTES)
        with _packs_lock(base):
            stored, outcome = add(
                base, config.packs.trusted_keys, data, signature, set(load_checks())
            )
    except (EvidenceError, OSError) as exc:
        print(f"checker: {exc.strerror if isinstance(exc, OSError) and exc.strerror else exc}",
              file=sys.stderr)  # fmt: skip
        return 1
    except StoreError as exc:
        print(f"checker: {args.file} wasn't added:", file=sys.stderr)
        for line in str(exc).splitlines():
            print(f"  {visible(line, 1000)}", file=sys.stderr)
        return 1
    pack = stored.pack
    print(
        f"{pack.id} version {pack.version} ({visible(pack.title, 200)}): {outcome}."
        f" Signed by {stored.signed_by.who} ({stored.signed_by.key.key_id})."
    )
    if outcome != "already in force":
        print("`checker analyze --all` applies it to every host's latest bundle.")
    return 0


def cmd_packs_list(args: argparse.Namespace) -> int:
    from checker.packs.store import active, retired
    from checker.report import visible

    base = home()
    try:
        config = load_config(base)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    usable, problems = active(base, config.packs.trusted_keys)
    if not usable:
        print("No pack is in force.")
    for stored in usable:
        pack = stored.pack
        print(
            f"{pack.id:28} v{pack.version:<4} {pack.published}  {visible(pack.title, 80)}"
            f"  (signed by {stored.signed_by.who})"
        )
    for problem in problems:
        print(f"checker: not used: {visible(problem, 300)}", file=sys.stderr)
    if args.retired:
        for pack_id, version, why in retired(base):
            print(f"retired: {pack_id} v{version}: {visible(why, 300)}")
    return 1 if problems else 0


def cmd_packs_show(args: argparse.Namespace) -> int:
    from checker.packs.store import active
    from checker.report import visible

    base = home()
    try:
        config = load_config(base)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    usable, _ = active(base, config.packs.trusted_keys)
    found = [s for s in usable if s.pack.id == args.id]
    if not found:
        print(f"checker: no pack {args.id!r} is in force", file=sys.stderr)
        return 1
    stored = found[-1]
    pack = stored.pack
    exposure = pack.exposure
    print(f"{pack.id} version {pack.version}, published {pack.published}")
    print(f"  {visible(pack.title, 200)}")
    signer = stored.signed_by
    print(f"  Signed by {signer.who} ({signer.key.key_id}); sha256 {stored.sha256}")
    if pack.cves:
        print(f"  CVEs: {', '.join(pack.cves)}")
    window = exposure.window_end.isoformat() if exposure.window_end else "still active"
    print(f"  Exposure window: {exposure.window_start.isoformat()} to {window}")
    print(f"  A host exposed through it: odds of compromise times {exposure.likelihood_ratio:g}")
    for entry in exposure.packages:
        which = f" (installed versions {entry.versions})" if entry.versions else ""
        fixed = entry.fixed or "no fix yet"
        print(f"  {entry.release}: {', '.join(entry.binary_names)}{which}: fixed in {fixed}")
    for mitigation in pack.mitigations:
        expect = visible(mitigation.expect, 100)
        print(f"  Mitigation {mitigation.id}: {mitigation.setting.name} = {expect}")
    for detection in pack.detections:
        ratio = f"{detection.likelihood_ratio:g}"
        print(f"  Detection {detection.id}: {detection.check} (LR {ratio} in the window)")
    return 0


def cmd_packs_retire(args: argparse.Namespace) -> int:
    from checker.packs.store import StoreError, retire

    base = home()
    try:
        with _packs_lock(base):
            names = retire(base, args.id, f"retired by hand: {args.reason}")
    except (StoreError, OSError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    print(f"Retired: {', '.join(names)} (kept in packs/retired/).")
    return 0


def cmd_packs_keys(args: argparse.Namespace) -> int:
    from checker.packs.trust import key_list, root_keys

    base = home()
    try:
        config = load_config(base)
    except EvidenceError as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    listed = key_list(base)
    if not root_keys():
        print("NouriLoop keys: none yet in this version of the tool.")
    elif listed is None:
        print("NouriLoop keys: no key list in force.")
    else:
        print(f"NouriLoop key list: serial {listed.serial}, issued {listed.issued}.")
        for entry in listed.pack_keys:
            from checker.packs.signing import public_key

            print(f"  trusted: {entry.name} ({public_key(entry.public_key).key_id})")
        for gone in listed.revoked:
            print(f"  revoked: {gone.key_id} since {gone.since}: {gone.reason}")
    if config.packs.trusted_keys:
        from checker.packs.signing import public_key

        print("Your organization's keys:")
        for entry in config.packs.trusted_keys:
            print(f"  {entry.name} ({public_key(entry.public_key).key_id})")
    return 0


def cmd_packs_keys_add(args: argparse.Namespace) -> int:
    from checker.packs.signing import MAX_SIGNATURE_BYTES
    from checker.packs.store import sweep
    from checker.packs.trust import TrustError, accept_key_list

    base = home()
    try:
        config = load_config(base)
        data = _read_untrusted(args.file, 64 * 1024)
        signature = _read_untrusted(args.signature or f"{args.file}.minisig", MAX_SIGNATURE_BYTES)
        with _packs_lock(base):
            new, old = accept_key_list(base, data, signature)
            retired = sweep(base, config.packs.trusted_keys)
    except (EvidenceError, OSError, TrustError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    print(f"Key list serial {new.serial} is in force" + (f" (was {old.serial})." if old else "."))
    for name in retired:
        print(f"Retired {name}: its signing key is no longer trusted.")
    return 0


def cmd_packs_trust_add(args: argparse.Namespace) -> int:
    from checker.packs.signing import SignatureError, public_key
    from checker.settings import change_trusted_keys

    base = home()
    try:
        key = public_key(_read_untrusted(args.key, 4096).decode("ascii", "replace"))
        current = [k.model_dump() for k in load_config(base).packs.trusted_keys]
        change_trusted_keys(base, [*current, {"name": args.name, "public_key": key.text}])
    except (EvidenceError, OSError, SignatureError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    print(f"Trusted for your packs: {args.name} ({key.key_id}). Recorded (checker config history).")
    return 0


def cmd_packs_trust_remove(args: argparse.Namespace) -> int:
    from checker.packs.store import sweep
    from checker.settings import change_trusted_keys

    base = home()
    try:
        current = [k.model_dump() for k in load_config(base).packs.trusted_keys]
        kept = [k for k in current if k["name"] != args.name]
        if len(kept) == len(current):
            raise EvidenceError(f"no trusted key is named {args.name!r}")
        with _packs_lock(base):
            _, _, config = change_trusted_keys(base, kept)
            retired = sweep(base, config.packs.trusted_keys)
    except (EvidenceError, OSError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 1
    print(f"No longer trusted: {args.name}. Recorded (checker config history).")
    for name in retired:
        print(f"Retired {name}: it was signed with that key.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """One pass, as a timer starts it: collect, analyze, report, purge what
    has expired, and alert on hosts that got worse (checker.schedule)."""
    import yaml

    from checker import schedule

    base = home()
    try:
        config = load_config(base)
        inventory = _inventory_for_priors()
        hosts = _select_hosts(args)
        identity = _identity(args, base)
    except (EvidenceError, KeyError, ValidationError, yaml.YAMLError) as exc:
        print(f"checker: {exc.args[0] if isinstance(exc, KeyError) else exc}", file=sys.stderr)
        return schedule.EXIT_SETUP
    if not hosts:
        print("checker: no hosts selected", file=sys.stderr)
        return schedule.EXIT_SETUP
    try:
        result = schedule.run(
            base, config, hosts, identity, inventory,
            unattended=args.unattended, days=args.days, parallel=args.parallel,
        )  # fmt: skip
    except schedule.Busy as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return schedule.EXIT_BUSY
    except Exception as exc:  # noqa: BLE001 - unforeseen: say so, and tell someone
        print(f"checker: the run stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        failed = schedule.notify_crash(config, exc)
        if failed:
            print(f"checker: the notify command failed too: {failed}", file=sys.stderr)
        return schedule.EXIT_FAILED
    for item in result.hosts:
        band = item.band or "-"
        shown = f" ({percent(item.probability)})" if item.probability is not None else ""
        print(f"{item.host:20} {item.collected:12} {band}{shown}")
        if item.problem:
            print(f"checker: {item.host}: {item.problem}", file=sys.stderr)
    for problem in result.problems:
        print(f"checker: {problem}", file=sys.stderr)
    if result.report:
        print(f"Report written to {result.report}")
    if result.alerting:
        print("\nNeeds a look:")
        for line in result.alerting:
            print(f"  {line}")
        if not config.notify_command:
            print("(No notify_command is set, so no one else was told.)")
        elif result.notified:
            print(
                f"checker: the notify command failed: {result.notified}; these are sent again"
                " with the next run's",
                file=sys.stderr,
            )
        else:
            print("The notify command was given the summary.")
    return result.exit_status()


def cmd_schedule_install(
    args: argparse.Namespace, pause: Callable[[float], None] | None = None
) -> int:
    import getpass
    import os
    import subprocess
    import time

    from checker import schedule

    pause = pause or time.sleep
    base = home()
    try:
        load_config(base)
        at = schedule.parse_time(args.at)
        hosts = load_inventory().hosts
    except (EvidenceError, ValueError) as exc:
        print(f"checker: {exc}", file=sys.stderr)
        return 2
    env = schedule.timer_environment(base, hosts)
    unsafe = schedule.systemd_unsafe(env) if sys.platform != "darwin" else []
    if unsafe:
        print(
            "checker: a systemd unit can't hold these paths (quotes, backslashes, $, ` or"
            " control characters): " + ", ".join(repr(w) for w in unsafe),
            file=sys.stderr,
        )
        return 2
    problems = schedule.unattended_problems(hosts)
    for problem in problems:
        print(f"Warning: {problem}")
    if problems:
        print("Until that changes, each scheduled run leaves those hosts out and says so.")
    if "SSH_AUTH_SOCK" in env:
        print(
            f"It uses the SSH agent at {env['SSH_AUTH_SOCK']}: its key must be unlocked when"
            " the run starts, or the run waits for a passphrase no one types."
        )
    if sys.platform == "darwin" and os.environ.get("SSH_CONNECTION"):
        print("A launchd agent runs while you are logged in at the Mac (not over SSH).")
    where = schedule.placement(sys.platform, at, env, base, Path.home())
    for path, content in where.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        print(f"Wrote {path}")
    if sys.platform == "darwin":
        (base / "logs").mkdir(exist_ok=True, mode=0o700)
        subprocess.run(where.stop[0], capture_output=True, check=False)  # noqa: S603 - a reload
    for command in where.start:
        # launchd may still be unloading the old agent: a few tries, a second apart.
        for _ in range(5 if sys.platform == "darwin" else 1):
            done = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
            if done.returncode == 0:
                break
            pause(1.0)
        if done.returncode != 0:
            print(
                f"checker: `{' '.join(command)}` failed: {(done.stderr or '').strip()}",
                file=sys.stderr,
            )
            return 1
    print(
        f"`checker run --all --unattended` will run every day at {args.at} (this machine's time)."
    )
    print(f"Its output: {where.logs}")
    if sys.platform != "darwin" and schedule.lingering(getpass.getuser()) is False:
        print(
            "It runs only while you are logged in. To run it at night with no one logged"
            f" in: sudo loginctl enable-linger {getpass.getuser()}"
        )
    return 0


def cmd_schedule_remove(args: argparse.Namespace) -> int:
    import subprocess

    from checker import schedule

    where = schedule.placement(sys.platform, (3, 0), {}, home(), Path.home())
    present = [path for path in where.files if path.exists()]
    if not present:
        print("No timer is installed.")
        return 0
    stop, *after = where.stop  # stopped while its files are there; reloaded once they're gone
    subprocess.run(stop, capture_output=True, check=False)  # noqa: S603
    for path in present:
        path.unlink()
        print(f"Deleted {path}")
    for command in after:
        subprocess.run(command, capture_output=True, check=False)  # noqa: S603
    print("Scheduled runs stopped.")
    return 0


def cmd_schedule_show(args: argparse.Namespace) -> int:
    from checker import schedule

    where = schedule.placement(sys.platform, (3, 0), {}, home(), Path.home())
    present = [path for path in where.files if path.exists()]
    if not present:
        print("No timer is installed: `checker schedule install --at HH:MM` adds one.")
        return 0
    for path in present:
        print(f"Installed: {path}")
    print(f"Output of past runs: {where.logs}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        print(f"checker {__version__}")
        parser.print_help()
        return 0
    return handler(args)

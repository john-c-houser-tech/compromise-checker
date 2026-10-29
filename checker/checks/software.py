"""Software changes (DESIGN.md §8.11): packages installed or removed,
repositories and signing keys added, attack tools and compilers appearing,
packages installed system-wide with pip or npm.

Updates are routine: package changes are low, and informational when an
automatic updater ran them or a maintenance window covers them."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, check, parse_time

ATTACK_TOOLS = {
    "nmap",
    "masscan",
    "zmap",
    "ncat",
    "nmap-ncat",
    "netcat-traditional",
    "proxychains",
    "proxychains4",
    "proxychains-ng",
    "chisel",
    "hydra",
    "medusa",
    "john",
    "hashcat",
    "sqlmap",
    "nikto",
    "responder",
    "impacket-scripts",
    "python3-impacket",
    "mimikatz",
    "sshuttle",
    "iodine",
    "dnscat2",
    "ligolo-ng",
}
# (cpp alone builds nothing; socat is left out: Kubernetes nodes need it.)
COMPILERS = {
    "gcc",
    "g++",
    "clang",
    "golang",
    "golang-go",
    "rustc",
    "cargo",
    "tcc",
    "build-essential",
}
# The automatic updaters' services (oneshot: systemd logs Starting… and
# Finished…, by unit name, or by description on older systemd). Not their
# timers (Started… at boot), nor PackageKit (apt starts it after any
# install), nor unattended-upgrades.service (a shutdown helper).
UPDATERS = (
    "apt-daily-upgrade.service",
    "Daily apt upgrade and clean activities",
    "dnf-automatic",
    "dnf automatic",
)
AFTER_RUN = timedelta(minutes=5)
RUN_LIMIT = timedelta(hours=4)
CLUSTER_GAP = timedelta(hours=6)
# Node.js's own package ships these in /usr/lib/node_modules.
BUNDLED_NODE = {"npm", "corepack"}
SHOWN = 8
# What makes a repository or key file's change real (not its times or inode).
MEANINGFUL = {"content_sha256", "sha256", "size", "mode", "uid", "gid", "link_target", "type"}
REPOSITORY_EXTENSIONS = (".list", ".sources", ".repo")
CONFIG_FILES = ("/etc/apt/sources.list", "/etc/dnf/", "/etc/yum.conf", "/etc/yum/vars/")
MAX_ENTITIES = 200


def _name(key: str) -> str:
    """The package's name from its snapshot key: `name arch`, or
    `name arch version` for packages installed side by side."""
    return key.split(" ", 1)[0]


def _time(value) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), UTC) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _updater_runs(context: Context) -> list[tuple[datetime, datetime]]:
    """(start, end) of each automatic updater run: a Starting… of an
    updater's service, to its Finished… (or four hours, if none)."""

    def updater(event) -> bool:
        what = str(event.fields.get("what") or "")
        return any(u.lower() in what.lower() for u in UPDATERS)

    finishes = [
        (str(e.fields.get("what")), t)
        for _, e in context.of("unit.finished")
        if updater(e) and (t := parse_time(e.corrected))
    ]
    runs = []
    for _, event in context.of("unit.starting"):
        start = parse_time(event.corrected)
        if not updater(event) or start is None:
            continue
        what = str(event.fields.get("what"))
        end = min(
            (t for w, t in finishes if w == what and start <= t <= start + RUN_LIMIT),
            default=start + RUN_LIMIT,
        )
        runs.append((start, end + AFTER_RUN))
    return runs


def _clusters(items: list[tuple[str, datetime | None]]) -> list[list[tuple[str, datetime | None]]]:
    """Installs grouped by when they happened (a gap of six hours starts a
    new group), so two patch nights are two findings; ones with no time
    are a group of their own."""
    timed = sorted((i for i in items if i[1] is not None), key=lambda i: i[1])
    groups: list[list[tuple[str, datetime | None]]] = []
    for item in timed:
        if groups and item[1] - groups[-1][-1][1] <= CLUSTER_GAP:
            groups[-1].append(item)
        else:
            groups.append([item])
    untimed = [i for i in items if i[1] is None]
    if untimed:
        groups.append(untimed)
    return groups


def _grouped(check_id, title, band, variant, names, refs, times, context, keys=()) -> Finding:
    shown = ", ".join(names[:SHOWN]) + (
        f" and {len(names) - SHOWN} more" if len(names) > SHOWN else ""
    )
    first = min(times).isoformat() if times else None
    last = max(times).isoformat() if times else None
    return Finding(
        check_id,
        title,
        COMPROMISE,
        band,
        f"{len(names)}: {shown}",
        [f"package:{n}" for n in names[:MAX_ENTITIES]],
        refs[:50],
        first,
        last,
        new=any(context.new_since_previous("packages", k) for k in keys),
        uncertain=context.uncertain("packages"),
        variant=variant,
        entities_complete=len(names) <= MAX_ENTITIES,
    )


@check(
    "software.packages",
    "Packages installed, removed or upgraded since the baseline",
    needs_baseline=True,
    variants=("installed", "removed", "upgraded", "automatic"),
)
def packages(context: Context) -> list[Finding]:
    diff = context.changes("packages")
    findings = []
    runs = _updater_runs(context)
    installed = [
        (k, _time(item.get("installed")))
        for k, item in sorted(diff["added"].items())
        if _name(k) != "gpg-pubkey"  # a signing key: software.repository
    ]
    for group in _clusters(installed):
        keys = [k for k, _ in group]
        times = [t for _, t in group if t is not None]
        # Every one dated, and inside an updater's run.
        automatic = len(times) == len(group) and all(
            any(start <= t <= end for start, end in runs) for t in times
        )
        findings.append(
            _grouped(
                "software.packages",
                "Packages installed since the baseline"
                + (" (by the automatic updater)" if automatic else ""),
                "info" if automatic else "low",
                "automatic" if automatic else "installed",
                [_name(k) for k in keys],
                [context.change_ref("packages", k, "added") for k in keys],
                times,
                context,
                keys,
            )
        )
    removed = sorted(diff["removed"])
    if removed and diff.get("comparable", True):
        findings.append(
            _grouped(
                "software.packages",
                "Packages removed since the baseline",
                "low",
                "removed",
                [_name(k) for k in removed],
                [context.change_ref("packages", k, "removed") for k in removed],
                [],
                context,
                removed,
            )
        )
    upgraded = sorted(k for k, fields in diff["changed"].items() if "version" in fields)
    if upgraded:
        times = [
            t
            for k in upgraded
            if (t := _time((context.items("packages").get(k) or {}).get("installed")))
        ]
        findings.append(
            _grouped(
                "software.packages",
                "Packages upgraded since the baseline",
                "info",
                "upgraded",
                [_name(k) for k in upgraded],
                [context.change_ref("packages", k, "changed") for k in upgraded],
                times,
                context,
                upgraded,
            )
        )
    return findings


@check(
    "software.repository",
    "New or changed package repositories and signing keys",
    needs_baseline=True,
    variants=("repository", "key"),
)
def repositories(context: Context) -> list[Finding]:
    """Repository and key files added, or changed in content or ownership
    (an upgrade rewriting a file unchanged is no change); keys rpm imported
    into its own database (gpg-pubkey packages). Files apt and dnf don't
    read (`.rpmnew`, `.save`, `.dpkg-dist`…) are low."""
    diff = context.changes("software_files")
    findings = []
    for how in ("added", "changed"):
        for path, item in diff[how].items():
            current = context.items("software_files").get(path, item)
            if current.get("type") == "d":
                continue
            if how == "changed" and not set(item) & MEANINGFUL:
                continue
            key = current.get("record") == "signing_key"
            read = key or path.endswith(REPOSITORY_EXTENSIONS) or path.startswith(CONFIG_FILES)
            findings.append(
                Finding(
                    "software.repository",
                    (
                        f"A package signing key was {how}"
                        if key
                        else f"A package repository was {how}"
                    )
                    + ("" if read else " (a file the package manager doesn't read)"),
                    COMPROMISE,
                    "medium" if read else "low",
                    path,
                    [f"path:{path}"],
                    [context.change_ref("software_files", path, how)],
                    new=context.new_since_previous("software_files", path),
                    uncertain=context.uncertain("software_files"),
                    variant="key" if key else "repository",
                )
            )
    for package, item in context.changes("packages")["added"].items():
        if _name(package) != "gpg-pubkey":
            continue
        findings.append(
            Finding(
                "software.repository",
                "A signing key was imported into rpm's database",
                COMPROMISE,
                "medium",
                f"gpg-pubkey {item.get('version')}",
                ["package:gpg-pubkey"],
                [context.change_ref("packages", package, "added")],
                new=context.new_since_previous("packages", package),
                uncertain=context.uncertain("packages"),
                variant="key",
            )
        )
    return findings


@check(
    "software.tools",
    "Attack and tunnelling tools, or compilers, installed since the baseline",
    needs_baseline=True,
    variants=("attack_tool", "compiler"),
)
def tools(context: Context) -> list[Finding]:
    diff = context.changes("packages")
    findings = []
    for key, item in diff["added"].items():
        name = _name(key)
        if name in ATTACK_TOOLS:
            title, band, variant = (
                "An attack or tunnelling tool was installed",
                "medium",
                "attack_tool",
            )
        elif name in COMPILERS:
            title, band, variant = "A compiler was installed", "low", "compiler"
        else:
            continue
        when = _time(item.get("installed"))
        findings.append(
            Finding(
                "software.tools",
                title,
                COMPROMISE,
                band,
                f"{name} {item.get('version') or ''}".strip(),
                [f"package:{name}"],
                [context.change_ref("packages", key, "added")],
                when.isoformat() if when else None,
                when.isoformat() if when else None,
                new=context.new_since_previous("packages", key),
                uncertain=context.uncertain("packages"),
                variant=variant,
            )
        )
    return findings


@check(
    "software.global", "Python and Node packages installed system-wide by hand", needs_baseline=True
)
def global_packages(context: Context) -> list[Finding]:
    diff = context.changes("global_packages")
    added: list[tuple[str, dict[str, Any]]] = sorted(
        (k, v)
        for k, v in diff["added"].items()
        if not (k.startswith("node: ") and k.split(": ", 1)[1] in BUNDLED_NODE)
    )
    if not added:
        return []
    names = [k.split(": ", 1)[1] for k, _ in added]
    shown = ", ".join(names[:SHOWN]) + (
        f" and {len(names) - SHOWN} more" if len(names) > SHOWN else ""
    )
    return [
        Finding(
            "software.global",
            "Packages installed system-wide with pip or npm since the baseline",
            COMPROMISE,
            "low",
            f"{len(names)}: {shown}",
            [f"package:{n}" for n in names[:MAX_ENTITIES]],
            [context.change_ref("global_packages", k, "added") for k, _ in added[:50]],
            new=any(context.new_since_previous("global_packages", k) for k, _ in added),
            uncertain=context.uncertain("global_packages"),
            entities_complete=len(names) <= MAX_ENTITIES,
        )
    ]

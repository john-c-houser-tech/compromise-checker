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
    "socat",
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
COMPILERS = {
    "gcc",
    "g++",
    "clang",
    "cpp",
    "golang",
    "golang-go",
    "rustc",
    "cargo",
    "tcc",
    "build-essential",
}
# Automatic updaters, by the description systemd logs when it starts them.
UPDATERS = (
    "apt-daily-upgrade",
    "unattended-upgrade",
    "Daily apt upgrade",
    "dnf-automatic",
    "dnf makecache",
    "yum-cron",
    "packagekit",
)
UPDATER_WINDOW = timedelta(hours=2)
SHOWN = 8
MAX_ENTITIES = 200


def _name(key: str) -> str:
    return key.rsplit(" ", 1)[0] if " " in key else key


def _time(value) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), UTC) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _updater_runs(context: Context) -> list[datetime]:
    return [
        t
        for _, e in context.of("unit.started")
        if any(u.lower() in str(e.fields.get("what") or "").lower() for u in UPDATERS)
        and (t := parse_time(e.corrected))
    ]


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
    updaters = _updater_runs(context)
    installed = sorted(diff["added"])
    if installed:
        times = [t for k in installed if (t := _time(diff["added"][k].get("installed")))]
        automatic = bool(times) and all(
            any(timedelta(0) <= t - u <= UPDATER_WINDOW for u in updaters) for t in times
        )
        findings.append(
            _grouped(
                "software.packages",
                "Packages installed since the baseline"
                + (" (by the automatic updater)" if automatic else ""),
                "info" if automatic else "low",
                "automatic" if automatic else "installed",
                [_name(k) for k in installed],
                [context.change_ref("packages", k, "added") for k in installed],
                times,
                context,
                installed,
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
    diff = context.changes("software_files")
    findings = []
    for how in ("added", "changed"):
        for path, item in diff[how].items():
            current = context.items("software_files").get(path, item)
            if current.get("type") == "d":
                continue
            key = current.get("record") == "signing_key"
            findings.append(
                Finding(
                    "software.repository",
                    f"A package signing key was {how}"
                    if key
                    else f"A package repository was {how}",
                    COMPROMISE,
                    "medium",
                    path,
                    [f"path:{path}"],
                    [context.change_ref("software_files", path, how)],
                    new=context.new_since_previous("software_files", path),
                    uncertain=context.uncertain("software_files"),
                    variant="key" if key else "repository",
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
    added: list[tuple[str, dict[str, Any]]] = sorted(diff["added"].items())
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

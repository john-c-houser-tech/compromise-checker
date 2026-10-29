"""Anti-forensics (DESIGN.md §8.10, ★ all): logs cleared or truncated,
logging and audit stopped or reconfigured, shell history switched off,
SELinux and AppArmor turned down, security agents stopped, the clock set.

Intruders cover their tracks; covering them leaves tracks of its own."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, check, parse_time

# Logs whose shrinking or vanishing matters most (by name, anywhere under
# /var/log): login records and the authentication, system and audit logs.
KEY_LOGS = re.compile(
    r"/(?:wtmp|btmp|lastlog|auth\.log|secure|syslog|messages|kern\.log|audit\.log)$"
)
ROTATED = re.compile(r"(?:\.\d+|-\d{8}|\.\d+\.gz|-\d{8}\.gz|\.old)$")
LOGGING_UNITS = re.compile(
    r"(?:auditd|Security Auditing|rsyslog|System Logging|systemd-journald|Journal Service"
    r"|syslog-ng)",
    re.IGNORECASE,
)
NEAR_SHUTDOWN = timedelta(minutes=15)
AUDIT_DISABLED = re.compile(r"\baudit_enabled=0\b|\bop=set\b.*\benabled=0\b")
REMOVE_RULE = re.compile(r"\bop=remove_rule\b")
ADD_RULE = re.compile(r"^type=CONFIG_CHANGE\b.*\bop=add_rule\b")
RESTART = timedelta(minutes=2)
RELOAD = timedelta(seconds=30)
ENFORCING_OFF = re.compile(r"\btype=MAC_STATUS\b.*\benforcing=0\b")
AUDIT_DAEMON_END = re.compile(r"^type=DAEMON_(?:END|ABORT)\b")
_AUDIT_TIME = re.compile(r"msg=audit\((\d+)\.\d+:\d+\)")
# Time synchronisation, including hypervisors' (Hyper-V, VMware, KVM).
NTP_DAEMONS = {
    "chronyd",
    "systemd-timesyncd",
    "ntpd",
    "openntpd",
    "timesyncd",
    "vmtoolsd",
    "hv_kvp_daemon",
    "qemu-ga",
    "phc2sys",
    "ptp4l",
}
# AppArmor profiles that come and go with VMs, containers and snaps.
TRANSIENT_PROFILES = re.compile(r"^(?:libvirt-|lxd-|docker-|snap\.|snap-update-ns\.|snap-|cri-)")
BOOT_SETTLING = timedelta(minutes=10)


def _shutdowns(context: Context) -> list:
    return [
        parse_time(e.corrected)
        for _, e in context.of("system.shutdown", "system.shutdown_requested", "system.boot")
        if parse_time(e.corrected)
    ]


def _near(moment, times, window=NEAR_SHUTDOWN) -> bool:
    return any(abs(moment - t) <= window for t in times)


def _files(snapshot) -> dict[str, dict[str, Any]]:
    if snapshot is None:
        return {}
    return {f["path"]: f for f in snapshot.live.get("log_files", []) if f.get("path")}


@check(
    "logs.cleared",
    "Logs cleared, truncated, replaced or deleted since the previous collection",
    variants=("truncated", "deleted", "replaced", "journal_removed"),
)
def cleared(context: Context) -> list[Finding]:
    """Against the previous bundle's log manifest: a log with the same inode
    but smaller is truncated, a key log gone is deleted, unless a rotated
    copy really holds the old log: one carrying its inode (rotation renames
    the file), or an uncompressed copy at least as large (copytruncate).
    A file merely named like a rotated copy proves nothing (anyone with root
    can create one); a compressed copy can't be checked by size, so the log
    is still reported, at medium, naming it."""
    before, now = _files(context.previous_snapshot), _files(context.snapshot)
    if not before or not now:
        return []
    # A listing cut short on either side: a missing log may just be unlisted.
    complete = not any(
        s is not None and s.live.get("log_manifest_truncated")
        for s in (context.previous_snapshot, context.snapshot)
    )
    findings = []

    def rotation(path: str, old: dict[str, Any]) -> str:
        """ "held" if a rotated copy holds the old log, "compressed" if only
        a compressed one might, else ""."""
        might = ""
        for other, info in now.items():
            if other == path or not other.startswith(path):
                continue
            if not ROTATED.search(other[len(path) :] or "x") or info.get("type") != "f":
                continue
            if info.get("inode") == old.get("inode"):
                return "held"
            if other.endswith((".gz", ".xz", ".bz2", ".zst")):
                if (info.get("mtime") or 0) >= (old.get("mtime") or 0):
                    might = other
            elif (info.get("size") or 0) >= (old.get("size") or 0) > 0:
                return "held"
        return might

    for path, old in before.items():
        if old.get("type") != "f":
            continue
        current = now.get(path)
        key = bool(KEY_LOGS.search(path))
        if current is None:
            how = "deleted"
            if not key or not complete:
                continue
        elif current.get("inode") == old.get("inode"):
            if (current.get("size") or 0) >= (old.get("size") or 0):
                continue
            how = "truncated"
        elif key:
            # A new file in its place (`sed -i`, or rm and touch): fine only
            # if rotation moved the old one aside.
            how = "replaced"
        else:
            continue
        rotated = rotation(path, old)
        if rotated == "held":
            continue
        band = "high" if key and not rotated else "medium"
        finding = _cleared(path, how, old, current, band)
        if rotated:
            finding.summary += f" (a compressed rotated copy exists, unverified: {rotated})"
        findings.append(finding)
    findings += _journal_removed(before, now, complete)
    return findings


def _journal_removed(before, now, complete) -> list[Finding]:
    """The persistent journal's folder or its active file gone (rm -rf
    /var/log/journal/*: journald then quietly keeps logs in memory only)."""
    if not complete:
        return []
    gone = sorted(
        path
        for path, info in before.items()
        if (path.endswith("/system.journal") or path == "/var/log/journal") and path not in now
    )
    return [
        Finding(
            "logs.cleared",
            "The persistent journal was removed",
            COMPROMISE,
            "high",
            f"{path} was there at the previous collection and isn't now",
            [f"path:{path}"],
            [],
            variant="journal_removed",
        )
        for path in gone[:5]
    ]


def _cleared(path, how, old, current, band) -> Finding:
    size = f"{old.get('size')} bytes" + (
        f" → {current.get('size')} bytes, same inode" if current else ""
    )
    return Finding(
        "logs.cleared",
        f"A log was {how} since the previous collection",
        COMPROMISE,
        band,
        f"{path}: {size}",
        [f"path:{path}"],
        [],
        variant=how,
    )


@check(
    "logs.stopped",
    "Logging or audit stopped, audit rules removed, audit switched off",
    variants=("unit", "audit_daemon", "audit_rules", "not_running", "moved"),
)
def stopped(context: Context) -> list[Finding]:
    shutdowns = _shutdowns(context)
    findings = []
    starts = [
        (str(e.fields.get("what") or ""), parse_time(e.corrected))
        for _, e in context.of("unit.started")
    ]
    for index, event in context.of("unit.stopped", "unit.failed"):
        what = str(event.fields.get("what") or event.fields.get("unit") or "")
        when = parse_time(event.corrected)
        if not LOGGING_UNITS.search(what) or when is None or _near(when, shutdowns):
            continue
        if any(name == what and t and timedelta(0) <= t - when <= RESTART for name, t in starts):
            continue  # restarted (an update, needrestart): not stopped
        findings.append(
            Finding(
                "logs.stopped",
                "A logging or audit service was stopped",
                COMPROMISE,
                "high",
                f"{what} ({event.type.split('.')[1]}) at {event.corrected}, not during a"
                " shutdown and not started again",
                [],
                [{"event": index}],
                event.corrected,
                event.corrected,
                variant="unit",
            )
        )
    records = []
    for line in context.snapshot.live.get("audit_records", []):
        stamp = _AUDIT_TIME.search(line)
        records.append((datetime.fromtimestamp(int(stamp.group(1)), UTC) if stamp else None, line))
    daemon_starts = [t for t, line in records if t and line.startswith("type=DAEMON_START")]
    rule_adds = [t for t, line in records if t and ADD_RULE.search(line)]
    removals = []
    for when, line in records:
        if AUDIT_DAEMON_END.search(line):
            if when is None or _near(when, shutdowns):
                continue
            if any(timedelta(0) <= t - when <= RESTART for t in daemon_starts):
                continue  # restarted (an update's condrestart)
            findings.append(
                _audit(
                    "The audit daemon stopped, not during a shutdown", line, when, "audit_daemon"
                )
            )
        elif line.startswith("type=CONFIG_CHANGE") and AUDIT_DISABLED.search(line):
            findings.append(_audit("Auditing was switched off", line, when, "audit_rules"))
        elif line.startswith("type=CONFIG_CHANGE") and REMOVE_RULE.search(line):
            # augenrules deletes every rule before loading them again: a
            # removal followed by additions within seconds is a reload.
            if when and any(timedelta(0) <= t - when <= RELOAD for t in rule_adds):
                continue
            removals.append((when, line))
    if removals:
        first = removals[0]
        findings.append(
            _audit(
                f"Audit rules were removed ({len(removals)}) and not loaded again",
                first[1],
                first[0],
                "audit_rules",
            )
        )
    changes = context.changes("logging")
    unknown = (context.items("logging").get("services") or {}).get("known") is False
    if changes is not None and not unknown:
        findings += _moved("service", changes, context)
        for key in changes["removed"]:
            if key.startswith("service: "):
                findings.append(
                    Finding(
                        "logs.stopped",
                        "A logging service that ran at the baseline isn't running",
                        COMPROMISE,
                        "high",
                        key.split(": ", 1)[1],
                        [f"program:{key.split(': ', 1)[1]}"],
                        [context.change_ref("logging", key, "removed")],
                        new=context.new_since_previous("logging", key),
                        uncertain=context.uncertain("logging"),
                        variant="not_running",
                    )
                )
    return findings


def _moved(kind: str, changes, context: Context) -> list[Finding]:
    """A service or agent now running from a different file (a fake with
    its name, in /dev/shm say)."""
    found = []
    for key, fields in changes["changed"].items():
        if not key.startswith(f"{kind}: ") or "exe" not in fields:
            continue
        old, new = fields["exe"]
        found.append(
            Finding(
                "logs.stopped" if kind == "service" else "agent.stopped",
                f"A {'logging service' if kind == 'service' else 'security agent'} runs from a"
                " different file than at the baseline",
                COMPROMISE,
                "high",
                f"{key.split(': ', 1)[1]}: {old} → {new}",
                [f"program:{key.split(': ', 1)[1]}"],
                [context.change_ref("logging", key, "changed")],
                new=context.new_since_previous("logging", key),
                variant="moved",
            )
        )
    return found


def _audit(title, line, when, variant) -> Finding:
    at = when.isoformat() if when else None
    return Finding(
        "logs.stopped",
        title,
        COMPROMISE,
        "high",
        line[:300],
        [],
        [],
        at,
        at,
        variant=variant,
    )


@check(
    "logs.journald_config", "journald set to keep nothing, or nothing on disk", needs_baseline=True
)
def journald(context: Context) -> list[Finding]:
    changes = context.changes("logging")
    changed = changes["changed"].get("journald") if changes else None
    now = (context.items("logging").get("journald") or {}).get("storage")
    if not changed or now not in ("none", "volatile"):
        return []
    return [
        Finding(
            "logs.journald_config",
            "journald was set to keep logs only in memory, or not at all",
            COMPROMISE,
            "high",
            f"Storage={now} since the baseline",
            [],
            [context.change_ref("logging", "journald", "changed")],
            new=context.new_since_previous("logging", "journald"),
        )
    ]


@check(
    "history.disabled",
    "Shell history switched off: linked to /dev/null, emptied, or disabled in start-up files",
    variants=("link", "emptied", "deleted", "startup"),
)
def history(context: Context) -> list[Finding]:
    findings = []
    for path, item in context.items("shell_history").items():
        target = str(item.get("link_target") or "")
        if item.get("type") == "l" and target in ("/dev/null", "../dev/null", "../../dev/null"):
            findings.append(
                Finding(
                    "history.disabled",
                    "A shell history file is a link to /dev/null",
                    COMPROMISE,
                    "high",
                    path,
                    [f"path:{path}"],
                    [{"item": ["shell_history", path]}],
                    variant="link",
                )
            )
    changes = context.changes("shell_history")
    if changes is not None and changes.get("comparable", True):
        for path in changes["removed"]:
            findings.append(
                Finding(
                    "history.disabled",
                    "A shell history file was deleted",
                    COMPROMISE,
                    "medium",
                    path,
                    [f"path:{path}"],
                    [context.change_ref("shell_history", path, "removed")],
                    new=context.new_since_previous("shell_history", path),
                    variant="deleted",
                )
            )
    if changes is not None:
        for path, fields in changes["changed"].items():
            size = fields.get("size")
            if isinstance(size, (list, tuple)) and len(size) == 2 and size[0] and not size[1]:
                findings.append(
                    Finding(
                        "history.disabled",
                        "A shell history file was emptied",
                        COMPROMISE,
                        "medium",
                        f"{path}: {size[0]} bytes → 0",
                        [f"path:{path}"],
                        [context.change_ref("shell_history", path, "changed")],
                        new=context.new_since_previous("shell_history", path),
                        variant="emptied",
                    )
                )
    for path, item in context.items("startup").items():
        if item.get("disables_history"):
            findings.append(
                Finding(
                    "history.disabled",
                    "A start-up file switches shell history off",
                    COMPROMISE,
                    "high",
                    f"{path} (unset HISTFILE, HISTSIZE=0, HISTFILE=/dev/null or set +o history)",
                    [f"path:{path}"],
                    [{"item": ["startup", path]}],
                    variant="startup",
                )
            )
    return findings


@check(
    "mac.disabled",
    "SELinux enforcement or AppArmor profiles turned down",
    variants=("selinux", "selinux_audit", "apparmor"),
)
def mac(context: Context) -> list[Finding]:
    findings = []
    for line in context.snapshot.live.get("audit_records", []):
        if ENFORCING_OFF.search(line):
            findings.append(
                Finding(
                    "mac.disabled",
                    "SELinux enforcement was switched off (setenforce 0)",
                    COMPROMISE,
                    "high",
                    line[:300],
                    [],
                    [],
                    variant="selinux_audit",
                )
            )
    changes = context.changes("logging")
    if changes is None:
        return findings
    selinux = changes["changed"].get("selinux")
    if selinux:
        mode = context.items("logging").get("selinux", {})
        if mode.get("mode") in ("permissive", "absent", "unknown") or mode.get("configured") in (
            "permissive",
            "disabled",
        ):
            findings.append(
                Finding(
                    "mac.disabled",
                    "SELinux was turned down since the baseline",
                    COMPROMISE,
                    "high",
                    f"now {mode.get('mode')}, configured {mode.get('configured')}",
                    [],
                    [context.change_ref("logging", "selinux", "changed")],
                    new=context.new_since_previous("logging", "selinux"),
                    variant="selinux",
                )
            )
    unloaded = sorted(
        k.split(": ", 1)[1]
        for k in changes["removed"]
        if k.startswith("apparmor: ") and not TRANSIENT_PROFILES.match(k.split(": ", 1)[1])
    )
    relaxed = sorted(
        k.split(": ", 1)[1]
        for k, fields in changes["changed"].items()
        if k.startswith("apparmor: ")
        and not TRANSIENT_PROFILES.match(k.split(": ", 1)[1])
        and isinstance(fields.get("mode"), (list, tuple))
        and fields["mode"][0] == "enforce"
    )
    profiles_then = [
        k.split(": ", 1)[1]
        for k in list(changes["removed"]) + list(context.items("logging"))
        if k.startswith("apparmor: ")
    ]
    before = sum(1 for name in profiles_then if not TRANSIENT_PROFILES.match(name))
    wholesale = before and (len(unloaded) + len(relaxed)) * 2 > before
    if unloaded or relaxed:
        shown = ", ".join((unloaded + relaxed)[:5])
        more = len(unloaded) + len(relaxed) - 5
        findings.append(
            Finding(
                "mac.disabled",
                "AppArmor profiles were unloaded or stopped enforcing",
                COMPROMISE,
                # Most or all of them: someone turned AppArmor down. A few:
                # an upgrade, a removed package.
                "high" if wholesale else "medium",
                f"{len(unloaded)} unloaded, {len(relaxed)} no longer enforcing: {shown}"
                + (f" and {more} more" if more > 0 else ""),
                [],
                [context.change_ref("logging", f"apparmor: {n}", "removed") for n in unloaded[:20]],
                new=True,
                uncertain=context.uncertain("logging"),
                variant="apparmor",
                entities_complete=False,
            )
        )
    return findings


@check(
    "agent.stopped",
    "Security agents that ran at the baseline and don't now",
    needs_baseline=True,
    variants=("moved",),
)
def agents(context: Context) -> list[Finding]:
    changes = context.changes("logging")
    if (context.items("logging").get("services") or {}).get("known") is False:
        return []  # no process listing this time: nothing to say
    return _moved("agent", changes, context) + [
        Finding(
            "agent.stopped",
            "A security agent that ran at the baseline isn't running",
            COMPROMISE,
            "high",
            key.split(": ", 1)[1],
            [f"program:{key.split(': ', 1)[1]}"],
            [context.change_ref("logging", key, "removed")],
            new=context.new_since_previous("logging", key),
            uncertain=context.uncertain("logging"),
        )
        for key in changes["removed"]
        if key.startswith("agent: ")
    ]


@check("clock.jump", "The system clock set by hand (not at boot)")
def clock(context: Context) -> list[Finding]:
    boots = [
        parse_time(e.corrected)
        for _, e in context.of("system.boot", "system.boot_journal")
        if parse_time(e.corrected)
    ]
    running = {
        str(p.get("exe") or "").rsplit("/", 1)[-1]
        for p in context.snapshot.live.get("processes", [])
    }
    synced = bool(running & NTP_DAEMONS)
    findings = []
    for index, event in context.of("system.clock_changed"):
        if str(event.fields.get("pid") or "1") != "1":
            continue  # a user's own systemd manager reporting it, not the system's
        when = parse_time(event.corrected)
        if when is None or any(timedelta(0) <= when - b <= BOOT_SETTLING for b in boots):
            continue
        findings.append(
            Finding(
                "clock.jump",
                "The system clock was changed",
                COMPROMISE,
                "low" if synced else "medium",
                f"at {event.corrected}"
                + (" (a time synchronisation daemon is running)" if synced else ""),
                [],
                [{"event": index}],
                event.corrected,
                event.corrected,
            )
        )
    return findings

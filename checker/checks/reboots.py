"""Reboots (DESIGN.md §8.2): each boot within the logs' reach classified as
unclean (no shutdown recorded: a crash or power loss), operator (a reboot
command through sudo just before), planned (an automatic updater ran just
before) or unexplained."""

from __future__ import annotations

import re
from datetime import timedelta

from checker.checks import COMPROMISE, Context, Finding, check, parse_time

SHUTDOWN = ("system.shutdown", "system.shutdown_record", "system.shutdown_requested")
REBOOT_COMMAND = re.compile(
    r"(?:^|/)(?:reboot|shutdown|poweroff|halt|telinit\s+[06]|init\s+[06])(?:\s|$)"
    r"|(?:^|/)systemctl\s+(?:.*\s)?(?:reboot|poweroff|halt|kexec)(?:\s|$)"
)
UPDATERS = re.compile(r"unattended[- ]upgrade|dnf[- ]automatic|yum-cron|apt-daily-upgrade", re.I)
OPERATOR_WINDOW = timedelta(minutes=15)
UPDATER_WINDOW = timedelta(minutes=60)


@check(
    "system.reboot",
    "Reboots: unclean, unexplained, by an operator or planned",
    variants=("unclean", "operator", "power_button", "planned", "unexplained"),
)
def reboots(context: Context) -> list[Finding]:
    boots = sorted(
        ((parse_time(e.corrected), i, e) for i, e in context.of("system.boot_journal")),
        key=lambda b: b[0] or parse_time("0001-01-01T00:00:00+00:00"),
    )
    boots = [b for b in boots if b[0] is not None]
    source = "the journal's boot list"
    # A volatile journal lists only the current boot: wtmp may know more.
    if len(boots) < 2:
        boots = sorted(
            (parse_time(e.corrected), i, e)
            for i, e in context.of("system.boot")
            if parse_time(e.corrected) is not None
        )
        source = "wtmp boot records"
        if len(boots) < 2:
            return []
    # How far back shutdowns can be seen: the oldest system journal or
    # login record event. A boot before that can't be classified.
    reach = [
        parse_time(e.corrected)
        for e in context.events
        if e.corrected and (e.source == "system_journal" or e.source.startswith("login_records"))
    ]
    if not boots or not reach:
        return []
    horizon = min(reach)
    shutdowns = [(parse_time(e.corrected), i, e) for i, e in context.of(*SHUTDOWN) if e.corrected]
    commands = [
        (parse_time(e.corrected), i, e)
        for i, e in context.of("sudo.command")
        if e.corrected and REBOOT_COMMAND.search(str(e.fields.get("command") or ""))
    ]
    updates = [
        (parse_time(e.corrected), i, e)
        for i, e in context.of("unit.started", "unit.stopped")
        if e.corrected and UPDATERS.search(str(e.fields.get("what") or ""))
    ]
    findings = []
    for (before, _, _), (started, index, boot) in zip(boots, boots[1:], strict=False):
        if before < horizon:
            continue  # the time before this boot isn't fully in the logs
        entities = [f"boot:{boot.fields.get('boot_id') or started.isoformat()}"]
        down = [s for s in shutdowns if before < s[0] <= started]
        if not down:
            findings.append(
                Finding(
                    "system.reboot",
                    "An unclean reboot: no shutdown was recorded before it",
                    COMPROMISE,
                    "medium",
                    f"booted {started.isoformat()} ({source}); a crash, a power loss or a"
                    " forced reset",
                    entities,
                    [{"event": index}],
                    started.isoformat(),
                    started.isoformat(),
                    variant="unclean",
                )
            )
            continue
        when = max(s[0] for s in down)
        evidence = [{"event": index}] + [{"event": s[1]} for s in down]
        by = [c for c in commands if when - OPERATOR_WINDOW <= c[0] <= when]
        # The power button (a cloud provider's console sends one too).
        button = [
            s
            for s in down
            if s[2].type == "system.shutdown_requested" and not s[2].fields.get("what")
        ]
        planned = [u for u in updates if when - UPDATER_WINDOW <= u[0] <= when]
        if by:
            users = sorted({c[2].fields.get("user", "?") for c in by})
            title, band, variant = "A reboot by an operator", "info", "operator"
            summary = f"booted {started.isoformat()}, after `sudo` by {', '.join(users)}"
            entities += [f"account:{u}" for u in users]
            evidence += [{"event": c[1]} for c in by]
        elif button:
            title, band, variant = "A reboot by the power button", "info", "power_button"
            summary = (
                f"booted {started.isoformat()}, after the power button was pressed (or a"
                " provider console's power-off)"
            )
        elif planned:
            title, band, variant = "A planned reboot (automatic updates)", "info", "planned"
            summary = f"booted {started.isoformat()}, after an automatic update"
            evidence += [{"event": u[1]} for u in planned]
        else:
            title, band, variant = "An unexplained reboot", "low", "unexplained"
            summary = (
                f"booted {started.isoformat()} after a clean shutdown that no operator command"
                " or automatic update explains"
            )
        findings.append(
            Finding(
                "system.reboot",
                title,
                COMPROMISE,
                band,
                summary,
                entities,
                evidence,
                when.isoformat(),
                started.isoformat(),
                variant=variant,
            )
        )
    return findings

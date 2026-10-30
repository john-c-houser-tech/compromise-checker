"""Better coverage, as the AI advisor may suggest it (Phase 3 plan, PR 3.4,
role 3). Every collector module always runs, so there are two levers, and
the advisor may only pick from them:

- the tool's own collection settings (`checker config set`), only to
  collect more than they do now (each step wider than the current value);
- a short catalogue of host configuration, each with the text an
  administrator applies by hand.

A suggestion is offered only when it names one of these and cites a
coverage gap (G-n, as the case listed them) or a finding (F-n) it would
help with. A setting is printed as the exact command for a person to run,
with the tool's own note on what it collects; host configuration as the
catalogue's text. Nothing runs or changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from checker.evidence import Config

# The settings a suggestion may change, each value from narrowest to
# widest, with what the wider ones collect.
SETTINGS: dict[str, dict[str, str]] = {
    "web_access_logs": {
        "off": "",
        "on": "web servers' access logs: every visitor's request and address, masked",
    },
    "exec_records": {
        "web": "",
        "privileged": "program starts by root, service and administrator accounts too",
        "all": "program starts by every account, ordinary users' included",
    },
    "home_text": {
        "off": "",
        "privileged": "start-up files and user units in privileged accounts' homes",
        "all": "start-up files and user units in every account's home",
    },
}
PRIVACY_NOTE = (
    "This collects more personal data from your servers (security and privacy"
    " policy §7): it is your organization's decision, and takes effect at the next"
    " collection."
)

# Host configuration an administrator applies; the tool never changes a host.
CATALOGUE: dict[str, dict[str, str]] = {
    "auditd-web-exec": {
        "title": "Record program starts by the web server's accounts (auditd)",
        "how": "Install auditd (Ubuntu: apt install auditd; RHEL: installed) and load"
        " docs/auditd-web.rules as its header says; exec_records is web by default.",
    },
    "auditd-running": {
        "title": "Run the audit daemon",
        "how": "Install auditd if it isn't (Ubuntu: apt install auditd), then"
        " systemctl enable --now auditd.",
    },
    "journald-persistent": {
        "title": "Keep the journal across reboots",
        "how": "Create /etc/systemd/journald.conf.d/persistent.conf holding a [Journal]"
        " line and a Storage=persistent line, then systemctl restart systemd-journald.",
    },
    "sshd-log-verbose": {
        "title": "Log which SSH key logged in",
        "how": "Put LogLevel VERBOSE in a file ending .conf in /etc/ssh/sshd_config.d/,"
        " named to sort before any other that sets LogLevel (sshd keeps the first value"
        " it reads), check with sshd -t, then systemctl reload ssh (Debian, Ubuntu) or"
        " systemctl reload sshd (RHEL and rebuilds).",
    },
    "web-log-format": {
        "title": "Use a web log format the tool reads",
        "how": "Log access in the combined format: nginx's default (access_log PATH"
        " combined); Apache's predefined one (CustomLog PATH combined).",
    },
    "log-retention": {
        "title": "Keep authentication logs for at least 30 days",
        "how": "Keep 5 or more weekly rotations: rotate in rsyslog's file in"
        " /etc/logrotate.d/ or, where it sets none, in /etc/logrotate.conf; for the"
        " journal, MaxRetentionSec=0 (or 30 days or more) and SystemMaxUse large"
        " enough.",
    },
}

REFERENCE = re.compile(r"([GF])-([1-9][0-9]{0,5})")


@dataclass
class Judged:
    suggestion: dict[str, Any]
    accepted: bool
    reason: str = ""  # why it was set aside
    action: str = ""  # the command, or the catalogue text (the tool's own)
    note: str = ""  # the tool's own note on what a setting collects
    cited: list[str] = field(default_factory=list)  # "G-2: <the gap as sent>", "F-1"


def judge(
    suggestions: list[dict[str, Any]], gaps: list[str], finding_ids: set[str], config: Config
) -> list[Judged]:
    """`gaps` are the coverage gaps as the case listed them (G-1…G-n)."""
    results, seen = [], set()
    for suggestion in suggestions:
        kind = suggestion.get("kind")
        refs = [str(r) for r in suggestion.get("helps_with") or []]
        problem, cited = None, []
        for ref in refs:
            found = REFERENCE.fullmatch(ref)
            if not found:
                problem = f"{ref} is neither a coverage gap (G-n) nor a finding (F-n)"
            elif found.group(1) == "G" and int(found.group(2)) > len(gaps):
                problem = f"{ref} isn't one of the case's {len(gaps)} coverage gaps"
            elif found.group(1) == "F" and ref not in finding_ids:
                problem = f"{ref} isn't a finding of the case"
            if problem:
                break
            if found.group(1) == "G":
                cited.append(f"{ref}: {gaps[int(found.group(2)) - 1]}")
            else:
                cited.append(ref)
        if not refs:
            problem = "it cites no coverage gap or finding it would help with"
        action, note, name = "", "", None
        if not problem and kind == "setting":
            name, value = str(suggestion.get("setting")), suggestion.get("value")
            steps = SETTINGS.get(name)
            if steps is None:
                problem = f"{name!r} isn't a collection setting a suggestion may change"
            elif value not in steps:
                problem = f"{name} can't be suggested as {value!r} (only {', '.join(steps)})"
            else:
                current = getattr(config, name)
                current = ("on" if current else "off") if isinstance(current, bool) else current
                order = list(steps)
                if order.index(value) <= order.index(current):
                    problem = (
                        f"{name} is {current}: {value} collects no more"
                        if value != current
                        else f"{name} is already {value}"
                    )
                else:
                    action = f"checker config set {name} {value}"
                    note = f"{steps[value][0].upper()}{steps[value][1:]}. {PRIVACY_NOTE}"
        elif not problem and kind == "host":
            name = str(suggestion.get("item"))
            item = CATALOGUE.get(name)
            if item is None:
                problem = f"{name!r} isn't in the host configuration catalogue"
            else:
                action = item["how"]
        elif not problem:
            problem = "its kind must be setting or host"
        if not problem and (kind, name) in seen:
            problem = "it repeats an earlier suggestion"
        if problem:
            results.append(Judged(suggestion, False, problem))
            continue
        seen.add((kind, name))
        results.append(Judged(suggestion, True, action=action, note=note, cited=cited))
    return results


def catalogue_text() -> str:
    """What the question tells the advisor it may pick from."""
    settings = "; ".join(
        f"{key}: {', '.join(f'{v} ({what})' for v, what in values.items() if what)}"
        for key, values in SETTINGS.items()
    )
    items = "; ".join(f"{key}: {item['title']}" for key, item in CATALOGUE.items())
    return (
        f"Settings (kind setting), only wider than they are now: {settings}."
        f" Host configuration (kind host): {items}."
    )

"""Better coverage, as the AI advisor may suggest it (Phase 3 plan, PR 3.4,
role 3). Every collector module always runs, so there are two levers, and
the advisor may only pick from them:

- the tool's own collection settings (`checker config set`), with the
  values those settings take;
- a short catalogue of host configuration, each with the text an
  administrator applies by hand.

A suggestion is offered only when it names one of these, cites a coverage
gap (G-n) or a finding (F-n) of the case it would help with, and (for a
setting) changes the current value. Settings are printed as the exact
command for a person to run; host configuration as text. Nothing runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from checker.evidence import Config

# The settings a suggestion may change, and the values it may suggest.
# Each opts in to collecting more (policy §7): the trade-off is privacy.
SETTINGS: dict[str, dict[str, str]] = {
    "web_access_logs": {
        "on": "collect web servers' access logs (visitors' requests), masked",
    },
    "exec_records": {
        "privileged": "program starts by root, service and administrator accounts too",
        "all": "program starts by every account",
    },
    "home_text": {
        "privileged": "start-up files and user units in privileged accounts' homes",
        "all": "start-up files and user units in every account's home",
    },
}

# Host configuration an administrator applies; the tool never changes a host.
CATALOGUE: dict[str, dict[str, str]] = {
    "auditd-web-exec": {
        "title": "Record program starts by the web server's accounts (auditd)",
        "how": "Install auditd and load docs/auditd-web.rules (see its header), then"
        " `checker config set exec_records web` (the default) or wider.",
        "closes": "earlier program starts by web accounts (a web shell's commands)",
    },
    "auditd-running": {
        "title": "Run the audit daemon",
        "how": "systemctl enable --now auditd",
        "closes": "audit records at all (program starts, rule changes)",
    },
    "journald-persistent": {
        "title": "Keep the journal across reboots",
        "how": "Set Storage=persistent in /etc/systemd/journald.conf (or a drop-in in"
        " /etc/systemd/journald.conf.d/), then systemctl restart systemd-journald.",
        "closes": "logs from before the last reboot",
    },
    "sshd-log-verbose": {
        "title": "Log which SSH key logged in",
        "how": "Set LogLevel VERBOSE in /etc/ssh/sshd_config (or a file in"
        " /etc/ssh/sshd_config.d/), then sshd -t && systemctl reload sshd.",
        "closes": "which key each login used",
    },
    "web-log-format": {
        "title": "Use a web log format the tool reads",
        "how": "Use the combined format (nginx: the default `combined`; Apache:"
        ' LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\"'
        ' \\"%{User-Agent}i\\"" combined) for access logs.',
        "closes": "web requests in logs whose format isn't recognised",
    },
    "log-retention": {
        "title": "Keep authentication logs for at least 30 days",
        "how": "In /etc/logrotate.d/ (rsyslog's file), rotate weekly with `rotate 5`"
        " or more; for the journal, leave SystemMaxUse large enough for 30 days.",
        "closes": "logins and sudo use further back than the logs now reach",
    },
}

REFERENCE = re.compile(r"([GF])-([1-9][0-9]{0,5})")


@dataclass
class Judged:
    suggestion: dict[str, Any]
    accepted: bool
    reason: str = ""  # why it was set aside
    action: str = ""  # the command, or the catalogue text


def judge(
    suggestions: list[dict[str, Any]], gaps: int, finding_ids: set[str], config: Config
) -> list[Judged]:
    """`gaps` is how many coverage gaps the case lists (G-1…G-n)."""
    results, seen = [], set()
    for suggestion in suggestions:
        kind = suggestion.get("kind")
        refs = [str(r) for r in suggestion.get("helps_with") or []]
        problem = None
        for ref in refs:
            found = REFERENCE.fullmatch(ref)
            if not found:
                problem = f"{ref} is neither a coverage gap (G-n) nor a finding (F-n)"
            elif found.group(1) == "G" and int(found.group(2)) > gaps:
                problem = f"{ref} isn't one of the case's {gaps} coverage gaps"
            elif found.group(1) == "F" and ref not in finding_ids:
                problem = f"{ref} isn't a finding of the case"
            if problem:
                break
        if not refs:
            problem = "it cites no coverage gap or finding it would help with"
        action = ""
        if not problem and kind == "setting":
            key, value = suggestion.get("setting"), suggestion.get("value")
            allowed = SETTINGS.get(str(key))
            if allowed is None:
                problem = f"{key!r} isn't a collection setting a suggestion may change"
            elif value not in allowed:
                problem = f"{key} can't be suggested as {value!r} (only {', '.join(allowed)})"
            else:
                current = getattr(config, key)
                current = ("on" if current else "off") if isinstance(current, bool) else current
                if current == value:
                    problem = f"{key} is already {value}"
                else:
                    action = f"checker config set {key} {value}"
        elif not problem and kind == "host":
            item = CATALOGUE.get(str(suggestion.get("item")))
            if item is None:
                problem = f"{suggestion.get('item')!r} isn't in the host configuration catalogue"
            else:
                action = item["how"]
        elif not problem:
            problem = "its kind must be setting or host"
        key = (kind, suggestion.get("setting") or suggestion.get("item"))
        if not problem and key in seen:
            problem = "it repeats an earlier suggestion"
        if problem:
            results.append(Judged(suggestion, False, problem))
            continue
        seen.add(key)
        results.append(Judged(suggestion, True, action=action))
    return results


def catalogue_text() -> str:
    """What the question tells the advisor it may pick from."""
    settings = "; ".join(
        f"{key}: {', '.join(f'{v} ({what})' for v, what in values.items())}"
        for key, values in SETTINGS.items()
    )
    items = "; ".join(f"{key}: {item['title']}" for key, item in CATALOGUE.items())
    return f"Settings (kind setting): {settings}. Host configuration (kind host): {items}."

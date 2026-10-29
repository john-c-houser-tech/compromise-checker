"""Web applications (DESIGN.md §8.12): what web workers start, requests
answered by scripts new since the baseline, attacks that got an answer,
bursts of errors, and the background noise every public site gets.

Request events are only the lines worth a look (checker.events.WebLogs):
5xx answers, attacks, scripts, files a site shouldn't serve; the rest are
counted per network in the snapshot's live part (`web_requests`)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any
from urllib.parse import unquote

from checker.checks import COMPROMISE, Context, Finding, check, parse_time, span
from checker.checks.files import SCRIPT
from checker.events import Event

WEB_USERS = {"www-data", "apache", "nginx", "http", "wwwrun", "lighttpd"}
# The processes that run web applications' code.
WEB_WORKERS = re.compile(r"^(?:php-fpm[\d.]*|php-cgi[\d.]*|lsphp[\d.]*|httpd|apache2|nginx)$")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "ash", "busybox"}
INTERPRETERS = re.compile(
    r"^(?:python[\d.]*|perl[\d.]*|ruby[\d.]*|php[\d.]*|node|nodejs|lua[\d.]*)$"
)
DOWNLOADERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ftp", "tftp", "scp", "sftp"}
RECON = {
    "id",
    "whoami",
    "uname",
    "hostname",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
    "ps",
    "w",
    "who",
    "last",
    "getent",
    "lsb_release",
}
READS_SECRETS = re.compile(r"/etc/(?:passwd|shadow|group|sudoers|hosts)\b")
# PHP's mail() runs the mailer through a shell: `sh -c "/usr/sbin/sendmail -t -i"`.
PHP_MAIL = re.compile(r"^(?:/bin/|/usr/bin/)?sh -c ['\"]?/usr/(?:s?bin|lib)/sendmail\b[^;&|`$()]*$")
# Programs that put a user in a login session: a web account's shell under
# one of these is an administrator's (sudo -u www-data bash), not the site's.
LOGIN_SESSION = {"sshd", "sudo", "su", "login", "runuser", "systemd-logind", "tmux", "screen"}
MAX_EVIDENCE = 50
ERROR_BURST = 20
ERROR_WINDOW = timedelta(minutes=5)
NOISE_FLOOR = 10  # refused requests, at the least, for the noise line
SHOWN = 5


def _basename(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[-1]


def _suspicious(program: str, command: str) -> str | None:
    """What kind of program a web worker shouldn't start, or None."""
    if PHP_MAIL.match(command.strip()):
        return None
    if program in SHELLS:
        return "a shell"
    if INTERPRETERS.match(program):
        return "an interpreter"
    if program in DOWNLOADERS:
        return "a download or network tool"
    if program in RECON:
        return "a reconnaissance command"
    if program in ("cat", "head", "tail", "less", "more") and READS_SECRETS.search(command):
        return "a read of system account files"
    return None


def web_uids(context: Context) -> dict[int, str]:
    """The web server's accounts on this host, by UID: the usual names and
    any the organization named at setup (`web_users`, which the collector
    records with the names it used)."""
    named = set((context.snapshot.live.get("web_accounts") or {}).get("names") or ())
    return {
        item["uid"]: name
        for name, item in context.items("accounts").items()
        if (name in WEB_USERS or name in named) and isinstance(item.get("uid"), int)
    }


def _names(context: Context) -> dict[Any, str]:
    return {
        item.get("uid"): name
        for name, item in context.items("accounts").items()
        if item.get("uid") is not None
    }


@check(
    "web.worker_child",
    "A web worker started a shell, interpreter, download tool or recon command",
    variants=("live", "history"),
)
def worker_child(context: Context) -> list[Finding]:
    """★ Live from the process list (its parent a web worker, or run by a
    web account outside a login session), and from the audit log's
    program starts by web accounts."""
    findings = []
    webs = web_uids(context)
    names = _names(context)
    processes = {p.get("pid"): p for p in context.snapshot.live.get("processes", [])}

    def ancestors(process):
        seen, current = [], processes.get(process.get("ppid"))
        while current is not None and len(seen) < 32 and current.get("pid") not in (0, 1):
            seen.append(current)
            current = processes.get(current.get("ppid"))
        return seen

    for pid, process in sorted(processes.items(), key=lambda p: str(p[0])):
        if process.get("kernel_thread"):
            continue
        program = _basename(process.get("exe")) or process.get("comm") or ""
        kind = _suspicious(program, process.get("cmdline") or "")
        if kind is None:
            continue
        chain = ancestors(process)
        parent = chain[0] if chain else {}
        parent_name = _basename(parent.get("exe")) or parent.get("comm") or ""
        uids = process.get("uids") or []
        uid = uids[0] if uids else None
        by_worker = bool(WEB_WORKERS.match(parent_name))
        as_web = uid in webs and not any(
            (_basename(a.get("exe")) or a.get("comm")) in LOGIN_SESSION for a in chain
        )
        if not (by_worker or as_web):
            continue
        account = names.get(uid, str(uid))
        findings.append(
            Finding(
                "web.worker_child",
                f"A web worker started {kind}",
                COMPROMISE,
                "high",
                f"{program} (pid {pid}, {account}), parent {parent_name or '?'}:"
                f" {(process.get('cmdline') or '')[:160]}",
                [f"account:{account}", f"program:{program}", f"pid:{pid}"]
                + ([f"exe:{process['exe']}"] if process.get("exe") else []),
                [{"live": ["processes", pid]}],
                process.get("start_time"),
                process.get("start_time"),
                variant="live",
            )
        )

    groups: dict[tuple[str, str], list[tuple[int, Event, str]]] = {}
    for index, event in context.of("process.exec"):
        f = event.fields
        uid = f.get("uid") if f.get("uid") in webs else f.get("euid")
        if uid not in webs:
            continue
        program = _basename(f.get("exe")) or f.get("comm") or ""
        kind = _suspicious(program, f.get("argv") or "")
        if kind is None:
            continue
        groups.setdefault((webs[uid], program), []).append((index, event, kind))
    for (account, program), found in sorted(groups.items()):
        events = [e for _, e, _ in found]
        first, last = span(events)
        example = (events[-1].fields.get("argv") or program)[:160]
        findings.append(
            Finding(
                "web.worker_child",
                f"A web account started {found[0][2]}",
                COMPROMISE,
                "high",
                f"{account} ran {program} {len(found)} time{'s' if len(found) != 1 else ''},"
                f" e.g. {example}",
                [f"account:{account}", f"program:{program}"],
                [{"event": i} for i, _, _ in found[:MAX_EVIDENCE]],
                first,
                last,
                variant="history",
            )
        )
    return findings


def _request_path(event: Event) -> str:
    return unquote((event.fields.get("path") or "").split("?", 1)[0])


@check(
    "web.new_script_hit",
    "Requests answered by a script new since the baseline",
    needs_baseline=True,
)
def new_script_hit(context: Context) -> list[Finding]:
    """A script added to a web root since the baseline (what files.web
    reports), then answered requests (2xx): a web shell in use."""
    diff = context.changes("web_files") or {}
    added = [path for path in diff.get("added", {}) if SCRIPT.search(_basename(path))]
    if not added:
        return []
    accounts = sorted(web_uids(context).values())
    hits: dict[str, list[tuple[int, Event]]] = {}
    for index, event in context.of("web.request"):
        status = event.fields.get("status")
        path = _request_path(event)
        if not isinstance(status, int) or not 200 <= status < 300 or len(path) < 2:
            continue
        if not path.startswith("/"):
            continue
        for script in added:
            # The request's path is the file's path below some web root.
            if script.endswith(path):
                hits.setdefault(script, []).append((index, event))
                break
    findings = []
    for script, found in sorted(hits.items()):
        events = [e for _, e in found]
        first, last = span(events)
        clients = sorted({e.fields.get("network") or "?" for e in events})
        findings.append(
            Finding(
                "web.new_script_hit",
                "A script new since the baseline answered requests",
                COMPROMISE,
                "high",
                f"{script}: {len(found)} request{'s' if len(found) != 1 else ''} answered, from"
                f" {', '.join(clients[:SHOWN])}",
                [f"path:{script}"] + [f"account:{a}" for a in accounts],
                [{"event": i} for i, _ in found[:MAX_EVIDENCE]]
                + [context.change_ref("web_files", script, "added")],
                first,
                last,
                uncertain=context.uncertain("web_files"),
            )
        )
    return findings


@check(
    "web.exploit",
    "Attack strings in web requests, answered or refused",
    variants=("answered", "refused"),
)
def exploit(context: Context) -> list[Finding]:
    """Per source network and attack: answered 2xx or 5xx (the application
    ran, or broke on it) medium; refused (3xx, 4xx) informational."""
    groups: dict[tuple[str, str, bool], list[tuple[int, Event]]] = {}
    for index, event in context.of("web.request"):
        status = event.fields.get("status")
        if not isinstance(status, int):
            continue
        answered = 200 <= status < 300 or status >= 500
        for attack in event.fields.get("attacks") or ():
            key = (event.fields.get("network") or "unknown", attack, answered)
            groups.setdefault(key, []).append((index, event))
    findings = []
    for (network, attack, answered), found in sorted(groups.items()):
        events = [e for _, e in found]
        first, last = span(events)
        statuses = sorted({str(e.fields.get("status")) for e in events})
        findings.append(
            Finding(
                "web.exploit",
                f"A {attack} attack {'answered' if answered else 'refused'}",
                COMPROMISE,
                "medium" if answered else "info",
                f"{network}: {len(found)} request{'s' if len(found) != 1 else ''}"
                f" (status {', '.join(statuses[:SHOWN])}), e.g. {events[0].fields.get('path')}"[
                    :300
                ],
                [f"network:{network}"],
                [{"event": i} for i, _ in found[:MAX_EVIDENCE]],
                first,
                last,
                variant="answered" if answered else "refused",
            )
        )
    return findings


@check("web.errors", "A burst of server errors from one source")
def errors(context: Context) -> list[Finding]:
    """20 or more 5xx answers or upstream errors from one network within
    five minutes: a scanner or an attack breaking the application."""
    by_network: dict[str, list[tuple[Any, int, Event]]] = {}
    for index, event in context.of("web.request", "web.error"):
        f = event.fields
        if event.type == "web.request" and not (
            isinstance(f.get("status"), int) and f["status"] >= 500
        ):
            continue
        if event.type == "web.error" and "upstream" not in (f.get("message") or ""):
            continue
        when = parse_time(event.corrected)
        if when is None or not f.get("network"):
            continue
        by_network.setdefault(f["network"], []).append((when, index, event))
    findings = []
    for network, found in sorted(by_network.items()):
        found.sort(key=lambda item: item[0])
        best: list[tuple[Any, int, Event]] = []
        start = 0
        for end in range(len(found)):
            while found[end][0] - found[start][0] > ERROR_WINDOW:
                start += 1
            if end - start + 1 > len(best):
                best = found[start : end + 1]
        if len(best) < ERROR_BURST:
            continue
        events = [e for _, _, e in best]
        first, last = span(events)
        findings.append(
            Finding(
                "web.errors",
                "A burst of server errors from one source",
                COMPROMISE,
                "low",
                f"{network}: {len(best)} errors within five minutes ({len(found)} in all)",
                [f"network:{network}"],
                [{"event": i} for _, i, _ in best[:MAX_EVIDENCE]],
                first,
                last,
            )
        )
    return findings


@check("web.noise", "Background noise: requests for paths the site doesn't have")
def noise(context: Context) -> list[Finding]:
    """DESIGN.md §17: the refused requests (3xx, 4xx) every public site
    gets, as one informational line, not a finding per source."""
    requests = (context.snapshot.live.get("web_requests") or {}).get("requests_by_network") or {}
    refused = {
        network: counts.get("3xx", 0) + counts.get("4xx", 0)
        for network, counts in requests.items()
        if counts.get("3xx", 0) + counts.get("4xx", 0)
    }
    total = sum(refused.values())
    if total < NOISE_FLOOR:
        return []
    top = sorted(refused.items(), key=lambda item: (-item[1], item[0]))
    return [
        Finding(
            "web.noise",
            "Background noise: requests for paths the site doesn't have",
            COMPROMISE,
            "info",
            f"{total} refused requests from {len(refused)} networks; most from "
            + ", ".join(f"{network} ({count})" for network, count in top[:SHOWN]),
            [f"network:{network}" for network, _ in top[:200]],
            [{"live": ["web_requests", 0]}],
            entities_complete=len(top) <= 200,
        )
    ]

"""Web applications (DESIGN.md §8.12): what web workers start, requests
answered by scripts new since the baseline, attacks that got an answer,
bursts of errors, and the background noise every public site gets.

Request events are only the lines worth a look (checker.events.WebLogs):
5xx answers, attacks, scripts, files a site shouldn't serve; the rest are
counted per network in the snapshot's live part (`web_requests`).

PHP runs every exec(), system() and shell_exec() through `sh -c`, and
sites run their own jobs as the web account, so a shell alone is no sign:
a shell is judged by what it was asked to do, and each program it started
by its own start; an administrator's or cron's session (the audit log's
login UID set) is left out, as the live rule leaves out login sessions."""

from __future__ import annotations

import posixpath
import re
from datetime import timedelta
from typing import Any
from urllib.parse import unquote

from checker.checks import COMPROMISE, Context, Finding, check, parse_time, span
from checker.checks.files import SCRIPT
from checker.events import WEB_SCRIPT_PATH, Event

WEB_USERS = {"www-data", "apache", "nginx", "http", "wwwrun", "lighttpd"}
# The processes that run web applications' code.
WEB_WORKERS = re.compile(r"^(?:php-fpm[\d.]*|php-cgi[\d.]*|lsphp[\d.]*|httpd|apache2|nginx)$")
# A web server's or PHP-FPM's systemd unit, in a process's cgroup.
WEB_UNIT = re.compile(
    r"/(?:nginx|apache2|httpd|php[\w.]*-fpm|php-fpm|lsws|lshttpd|litespeed)[\w@.-]*\.service\b"
)
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "ash", "busybox"}
INTERPRETERS = re.compile(
    r"^(?:python[\d.]*|perl[\d.]*|ruby[\d.]*|php[\d.]*|node|nodejs|lua[\d.]*)$"
)
NETWORK_TOOLS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ftp",
    "tftp",
    "scp",
    "sftp",
    "telnet",
    "openssl",
}
SCHEDULERS = {"crontab", "at", "batch"}
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
# What a shell asked to run something (`sh -c …`) is judged on: a reverse
# shell, a download piped to a shell, decoding a payload, a scratch place.
SHELL_DANGER = re.compile(
    r"/dev/(?:tcp|udp)/|\|\s*(?:ba|da|z)?sh\b|base64\s+(?:-d|--decode)|\bmkfifo\b"
    r"|\b(?:curl|wget|nc|ncat|socat|telnet)\b|\bopenssl\s+s_client\b|\bpython[\d.]*\s+-c\b"
    r"|\bperl\s+-e\b|\bphp\s+-r\b|\b(?:ba)?sh\s+-i\b|\bchmod\s+(?:\+|[0-7]*[1357][0-7]*\b)"
    r"|/(?:tmp|dev/shm|var/tmp)/"
)
# Programs run from where nothing installed should run from.
OUTSIDE = re.compile(r"^/(?:tmp|var/tmp|dev/shm|var/www|srv|run/user|home)/")
# PHP's mail() runs the mailer through a shell: `sh -c "/usr/sbin/sendmail
# -t -i"` (options and addresses only).
PHP_MAIL = re.compile(
    r"^(?:/bin/|/usr/bin/)?sh -c ['\"]?/usr/(?:s?bin|lib)/(?:sendmail|msmtp|ssmtp)"
    r"(?: +[-\w.@+=']+)*['\"]?$"
)
# Programs that put a user in a login session: a web account's shell under
# one of these is an administrator's (sudo -u www-data bash), not the site's.
LOGIN_SESSION = {
    "sshd",
    "sudo",
    "su",
    "login",
    "runuser",
    "systemd-logind",
    "tmux",
    "screen",
    "cron",
    "crond",
}
AUID_UNSET = 4294967295
MAX_EVIDENCE = 50
ERROR_BURST = 20
ERROR_WINDOW = timedelta(minutes=5)
NOISE_FLOOR = 10  # refused requests, at the least, for the noise line
SHOWN = 5


def _program(path: str | None, comm: str | None = None) -> str:
    """A program's name from the file it runs (a deleted one's too)."""
    name = (path or "").removesuffix(" (deleted)").rsplit("/", 1)[-1]
    return name or comm or ""


def _shell_text(command: str) -> str | None:
    """What `sh -c TEXT` was asked to run, or None for a shell not run with
    a command (an interactive one, or `-i`)."""
    words = command.split(None, 2)
    if len(words) >= 3 and words[1] in ("-c", "-ec", "-ce"):
        return words[2]
    return None


def judge(program: str, command: str, exe: str | None = None) -> tuple[str, str] | None:
    """(what it is, band) for a program a web worker shouldn't start, or
    None. A shell given a command is judged by the command; the programs
    that command starts are judged by their own starts."""
    if exe and OUTSIDE.match(exe):
        return "a program outside the system directories", "high"
    if program in SHELLS:
        text = _shell_text(command)
        if text is None:
            return "an interactive shell", "high"
        if PHP_MAIL.match(command.strip()):
            return None
        first = _program(text.strip().strip("'\"").split(" ", 1)[0])
        chained = {_program(w) for w in re.split(r"[;&|`]+|\$\(", text)[1:] for w in w.split()[:1]}
        if (
            SHELL_DANGER.search(text)
            or first in RECON
            or chained & RECON
            or READS_SECRETS.search(text)
        ):
            return "a shell running an attacker's command", "high"
        return None
    if INTERPRETERS.match(program):
        return "an interpreter", "medium"
    if program in NETWORK_TOOLS:
        return "a download or network tool", "high"
    if program in SCHEDULERS:
        return "a scheduling tool", "high"
    if program in RECON:
        return "a reconnaissance command", "high"
    if program in ("cat", "head", "tail", "less", "more") and READS_SECRETS.search(command):
        return "a read of system account files", "high"
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


def _after_previous(context: Context, moment: str | None) -> bool:
    previous, at = parse_time(context.previous_time), parse_time(moment)
    return previous is None or at is None or at > previous


def _cited(found: list[tuple]) -> list[dict[str, int]]:
    """The first and the newest events of a group, MAX_EVIDENCE at most."""
    indexes = [item[0] for item in found]
    if len(indexes) > MAX_EVIDENCE:
        indexes = indexes[: MAX_EVIDENCE // 2] + indexes[-MAX_EVIDENCE // 2 :]
    return [{"event": i} for i in indexes]


@check(
    "web.worker_child",
    "A web worker started a shell, interpreter, download tool or recon command",
    variants=("live", "history"),
)
def worker_child(context: Context) -> list[Finding]:
    """★ Live from the process list (its parent a web worker, or run by a
    web account inside a web server's own service, outside any login), and
    from the audit log's program starts by web accounts outside any login
    or cron session (login UID unset)."""
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

    def uid_of(process):
        uids = process.get("uids") or []
        return uids[0] if uids else None

    for pid, process in sorted(processes.items(), key=lambda p: str(p[0])):
        if process.get("kernel_thread"):
            continue
        program = _program(process.get("exe"), process.get("comm"))
        judged = judge(program, process.get("cmdline") or "", process.get("exe"))
        if judged is None:
            continue
        chain = ancestors(process)
        parent = chain[0] if chain else {}
        parent_name = _program(parent.get("exe"), parent.get("comm"))
        uid = uid_of(process)
        # A root web server's own root helpers (piped loggers) aren't the site's.
        by_worker = bool(WEB_WORKERS.match(parent_name)) and not (uid == 0 and uid_of(parent) == 0)
        as_web = (
            uid in webs
            and bool(WEB_UNIT.search(process.get("cgroup") or ""))
            and not any(_program(a.get("exe"), a.get("comm")) in LOGIN_SESSION for a in chain)
        )
        if not (by_worker or as_web):
            continue
        kind, band = judged
        account = names.get(uid, str(uid))
        findings.append(
            Finding(
                "web.worker_child",
                f"A web worker started {kind}",
                COMPROMISE,
                band,
                f"{program} (pid {pid}, {account}), parent {parent_name or '?'}:"
                f" {(process.get('cmdline') or '')[:160]}",
                [f"account:{account}", f"program:{program}", f"pid:{pid}"]
                + ([f"exe:{process['exe']}"] if process.get("exe") else []),
                [{"live": ["processes", pid]}],
                process.get("start_time"),
                process.get("start_time"),
                new=_after_previous(context, process.get("start_time")),
                variant="live",
            )
        )

    groups: dict[tuple[str, str, str], list[tuple[int, Event, tuple[str, str]]]] = {}
    for index, event in context.of("process.exec"):
        f = event.fields
        if f.get("success") is False:
            continue  # a failed start (a shell's search along PATH)
        uid = f.get("uid") if f.get("uid") in webs else f.get("euid")
        if uid not in webs:
            continue
        if f.get("auid") not in (None, AUID_UNSET):
            continue  # an administrator's or a cron job's session, not the site's
        program = _program(f.get("exe"), f.get("comm"))
        command = f.get("argv") or ""
        judged = judge(program, command, f.get("exe"))
        if judged is None:
            continue
        # One finding per kind of command: an attacker's among a site's own
        # jobs stays apart.
        text = _shell_text(command) if program in SHELLS else None
        head = _program((text or command).strip("'\" ").split(" ", 1)[0]) or program
        groups.setdefault((webs[uid], program, head), []).append((index, event, judged))
    for (account, program, _), found in sorted(groups.items()):
        events = [e for _, e, _ in found]
        first, last = span(events)
        kind, band = max((j for _, _, j in found), key=lambda j: j[1] == "high")
        example = (events[-1].fields.get("argv") or program)[:160]
        findings.append(
            Finding(
                "web.worker_child",
                f"A web account started {kind}",
                COMPROMISE,
                band,
                f"{account} ran {program} {len(found)} time{'s' if len(found) != 1 else ''},"
                f" e.g. {example}",
                [f"account:{account}", f"program:{program}"],
                _cited(found),
                first,
                last,
                variant="history",
            )
        )
    return findings


def request_path(event: Event) -> str:
    """A request's file path: decoded, normalised (// and /./ and ..), and
    cut after a script's name (/x.php/extra is x.php's PATH_INFO)."""
    raw = unquote((event.fields.get("path") or "").split("?", 1)[0])
    if not raw.startswith("/"):
        return ""
    path = "/" + posixpath.normpath(raw).lstrip("/")
    parts = path.split("/")
    for i, part in enumerate(parts):
        if i and SCRIPT.search(part):
            return "/".join(parts[: i + 1])
    return path


@check(
    "web.new_script_hit",
    "Requests answered by a script new since the baseline",
    needs_baseline=True,
)
def new_script_hit(context: Context) -> list[Finding]:
    """A script added to a web root since the baseline (what files.web
    reports), then answered requests (2xx): a web shell in use. Uncertain
    when a file there before also ends in the request's path (two sites)."""
    diff = context.changes("web_files") or {}
    added = [path for path in diff.get("added", {}) if SCRIPT.search(_program(path))]
    if not added:
        return []
    items = context.items("web_files")
    older = [p for p in items if p not in diff.get("added", {})]
    webs = web_uids(context)
    hits: dict[str, list[tuple[int, Event]]] = {}
    ambiguous: set[str] = set()
    for index, event in context.of("web.request"):
        status = event.fields.get("status")
        path = request_path(event)
        if not isinstance(status, int) or not 200 <= status < 300 or len(path) < 2:
            continue
        for script in added:
            # The request's path is the file's path below some web root.
            if script.endswith(path):
                hits.setdefault(script, []).append((index, event))
                if any(o.endswith(path) for o in older):
                    ambiguous.add(script)
                break
    findings = []
    for script, found in sorted(hits.items()):
        events = [e for _, e in found]
        first, last = span(events)
        clients = sorted({e.fields.get("network") or "?" for e in events})
        owner = webs.get((items.get(script) or {}).get("uid"))
        uncertain = context.uncertain("web_files")
        if script in ambiguous:
            uncertain = "another site's file of the same path may have answered"
        findings.append(
            Finding(
                "web.new_script_hit",
                "A script new since the baseline answered requests",
                COMPROMISE,
                "high",
                f"{script}: {len(found)} request{'s' if len(found) != 1 else ''} answered, from"
                f" {', '.join(clients[:SHOWN])}",
                # The account: the web account that owns the file (as one a
                # web shell wrote does), never every web account.
                [f"path:{script}"] + ([f"account:{owner}"] if owner else []),
                _cited(found) + [context.change_ref("web_files", script, "added")],
                first,
                last,
                new=_after_previous(context, last),
                uncertain=uncertain,
            )
        )
    return findings


def _cgi(path: str) -> bool:
    return "/cgi-bin/" in path or path.split("?", 1)[0].endswith(".cgi")


@check(
    "web.exploit",
    "Attack strings in web requests, answered or refused",
    variants=("answered", "refused"),
)
def exploit(context: Context) -> list[Finding]:
    """Per source network and attack. Answered (medium): a script took the
    attack in its request and answered 2xx, or the server failed (5xx); a
    Shellshock user agent a CGI program answered. Anything else — static
    pages, front controllers ignoring a parameter, user agents — refused
    (informational): scanners send these to every site."""
    groups: dict[tuple[str, str, bool], list[tuple[int, Event]]] = {}
    for index, event in context.of("web.request"):
        f = event.fields
        status = f.get("status")
        if not isinstance(status, int):
            continue
        path = f.get("path") or ""
        script = bool(WEB_SCRIPT_PATH.search(path)) and request_path(event) != "/"
        network = f.get("network") or "unknown"
        for attack in f.get("attacks") or ():
            answered = status >= 500 or (200 <= status < 300 and script)
            groups.setdefault((network, attack, answered), []).append((index, event))
        for attack in f.get("agent_attacks") or ():
            answered = attack == "shellshock" and _cgi(path) and 200 <= status < 300
            groups.setdefault((network, attack, answered), []).append((index, event))
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
                [f"address:{network}"] if network != "unknown" else [],
                _cited(found),
                first,
                last,
                variant="answered" if answered else "refused",
                entities_complete=network != "unknown",
            )
        )
    return findings


@check("web.errors", "A burst of server errors from one source")
def errors(context: Context) -> list[Finding]:
    """20 or more 5xx answers or upstream errors from one network within
    five minutes: a scanner, or an attack breaking the application. Error
    lines count only for a network with no 5xx in the access log (nginx
    logs a failed upstream twice)."""
    answered: dict[str, list[tuple[Any, int, Event]]] = {}
    upstream: dict[str, list[tuple[Any, int, Event]]] = {}
    for index, event in context.of("web.request", "web.error"):
        f = event.fields
        when = parse_time(event.corrected)
        if when is None or not f.get("network"):
            continue
        status = f.get("status")
        if event.type == "web.request" and isinstance(status, int) and status >= 500:
            answered.setdefault(f["network"], []).append((when, index, event))
        elif event.type == "web.error" and "upstream" in (f.get("message") or ""):
            upstream.setdefault(f["network"], []).append((when, index, event))
    findings = []
    for network in sorted(set(answered) | set(upstream)):
        found = sorted(answered.get(network) or upstream.get(network) or [], key=lambda x: x[0])
        best_start = best_end = start = 0
        for end in range(len(found)):
            while found[end][0] - found[start][0] > ERROR_WINDOW:
                start += 1
            if end - start > best_end - best_start:
                best_start, best_end = start, end
        size = best_end - best_start + 1 if found else 0
        if size < ERROR_BURST:
            continue
        best = found[best_start : best_end + 1]
        events = [e for _, _, e in best]
        first, last = span(events)
        findings.append(
            Finding(
                "web.errors",
                "A burst of server errors from one source",
                COMPROMISE,
                "low",
                f"{network}: {size} errors within five minutes ({len(found)} in all)",
                [f"address:{network}"] if network != "unknown" else [],
                [{"event": i} for _, i, _ in best[:MAX_EVIDENCE]],
                first,
                last,
                entities_complete=network != "unknown",
            )
        )
    return findings


@check("web.noise", "Background noise: requests for paths the site doesn't have")
def noise(context: Context) -> list[Finding]:
    """DESIGN.md §17: the refused requests (3xx, 4xx) every public site
    gets, as one informational line, not a finding per source: the counted
    ones, and refused requests kept as events (for scripts) that carried
    no attack."""
    requests = (context.snapshot.live.get("web_requests") or {}).get("requests_by_network") or {}
    refused = {
        network: counts.get("3xx", 0) + counts.get("4xx", 0)
        for network, counts in requests.items()
        if counts.get("3xx", 0) + counts.get("4xx", 0)
    }
    for _, event in context.of("web.request"):
        f = event.fields
        status = f.get("status")
        if isinstance(status, int) and 300 <= status < 500 and not f.get("attacks"):
            network = f.get("network") or "unknown"
            refused[network] = refused.get(network, 0) + 1
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
            [f"address:{network}" for network, _ in top[:200] if network != "unknown"],
            [{"live": ["web_requests", 0]}],
            entities_complete=len(top) <= 200 and "unknown" not in refused,
        )
    ]

"""The HTML report (DESIGN.md §13): one self-contained file per run, marked
confidential (policy §8), from each host's latest assessment.

Everything in it that came from a host — file names, log lines, command
lines — is the host's own text, which an intruder may have chosen: it is
HTML-escaped, control and bidirectional characters are shown as visible
escapes (so one name can't display as another), and the page loads nothing
from anywhere (its Content-Security-Policy forbids it)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import unicodedata
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pyrage
from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup
from pyrage import x25519

from checker import __version__
from checker.analysis import load_events, snapshot_of
from checker.assess import (
    analyze,
    count,
    events_of,
    load_assessment,
    packs_applied,
    store_assessment,
)
from checker.baseline import USABLE, usable_bundles
from checker.checks import BANDS, CATEGORIES, CHECKS_VERSION
from checker.correlate import find_chains
from checker.evidence import EvidenceError, Store, open_text, who_and_where
from checker.scoring import DEFAULT_PRIOR, percent, prior_raise_of, score
from checker.snapshot import Snapshot
from checker.whitelist import Whitelist, reapply

MAX_EVIDENCE = 5  # excerpts shown per finding
MAX_TIMELINE = 300
MAX_MARKED = 20  # threat packs whose window the timeline marks (four marks each at most)
MAX_TEXT = 300


def current_versions() -> dict[str, int]:
    """What an assessment's evidence references depend on."""
    from checker.events import PARSER_VERSION
    from checker.scoring import SCORING_VERSION
    from checker.snapshot import SNAPSHOT_VERSION

    return {
        "checks": CHECKS_VERSION,
        "parser": PARSER_VERSION,
        "snapshot": SNAPSHOT_VERSION,
        "scoring": SCORING_VERSION,
    }


class Shown(str):
    """Text already made visible: printed as it is (then HTML-escaped)."""


# Characters that show as nothing, or change how what's around them looks:
# controls, formats (bidirectional overrides, zero-width), private use,
# surrogates, unassigned, combining and enclosing marks (an overlay can
# strike a name through), separators and every space but the plain one.
HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Mn", "Me", "Zl", "Zp", "Zs"}
# Letters that display as blanks (Hangul fillers, the braille blank).
BLANK_LETTERS = {"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800"}


def _escape(char: str) -> str:
    if char == "\\":
        return "\\\\"  # so a host can't write a fake escape: \\u202e
    if char != " " and (unicodedata.category(char) in HIDDEN_CATEGORIES or char in BLANK_LETTERS):
        code = ord(char)
        return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
    return char


def visible(value: Any, limit: int = MAX_TEXT) -> Shown:
    """Host text made safe to show: every character that displays as
    nothing or disguises what's around it becomes an escape like \\u202e (a
    backslash itself is doubled, so an escape can't be faked); cut at
    `limit` characters of output, never inside an escape."""
    if isinstance(value, Shown):
        return value
    if value is None:
        return Shown("")
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    out, length = [], 0
    for char in text:
        piece = _escape(char)
        if length + len(piece) > limit:
            out.append("…")
            break
        out.append(piece)
        length += len(piece)
    return Shown("".join(out))


def _finalize(value: Any) -> Any:
    """Jinja's last step for every printed value: the template's own markup
    (macros) passes; everything else is made visible, whether or not the
    template asked."""
    if isinstance(value, Markup):
        return value
    return visible(value)


def _brief(item: dict | None, limit: int = MAX_TEXT) -> str:
    if not item:
        return "(none)"
    return visible(
        " ".join(f"{k}={v}" for k, v in item.items() if v not in (None, "", [], {})), limit
    )


@dataclass
class HostReport:
    host: str
    row: Any
    assessment: dict
    manifest: dict
    custody: list
    findings: dict[str, list[dict]] = field(default_factory=dict)  # by category
    suppressed: list[dict] = field(default_factory=list)  # whitelisted, for the appendix
    timeline: list[dict] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    # The advisor's latest record per role for this bundle (policy §9).
    advice: dict[str, dict] = field(default_factory=dict)
    # What the findings' evidence points into, for the advisor's case file.
    events: list = field(default_factory=list)
    snapshot: Snapshot | None = None
    baselines: dict[str, Snapshot | None] = field(default_factory=dict)


def excerpts(
    finding: dict, events, snapshot: Snapshot, baselines: dict[str, Snapshot]
) -> list[dict]:
    """What each piece of a finding's evidence says, briefly. A log excerpt's `where` is the
    log's name, which the host chose: a page that boxes server text should box that too."""
    shown = []
    for ref in finding.get("evidence", [])[:MAX_EVIDENCE]:
        if "event" in ref and 0 <= ref["event"] < len(events):
            event = events[ref["event"]]
            shown.append(
                {
                    "when": event.corrected[:19]
                    if event.corrected
                    else (f"{event.time[:19]} (host clock)" if event.time else ""),
                    "where": visible(event.source, 80),
                    "text": visible(event.line)
                    if event.line
                    else Shown(f"{event.type} {_brief(event.fields)}"),
                }
            )
        elif "item" in ref:
            section, key = ref["item"]
            item = (
                snapshot.sections.get(section).items if section in snapshot.sections else {}
            ).get(key)
            shown.append(
                {"when": "", "where": section, "text": Shown(f"{visible(key)}: {_brief(item)}")}
            )
        elif "change" in ref:
            against, section, key, how = ref["change"]
            now = snapshot.sections.get(section)
            current = (now.items if now else {}).get(key)
            before_snapshot = baselines.get(against)
            then = before_snapshot.sections.get(section) if before_snapshot else None
            previous = (then.items if then else {}).get(key)
            if how == "added":
                text = Shown(f"added: {visible(key)}: {_brief(current)}")
            elif how == "removed":
                text = Shown(f"removed: {visible(key)}: {_brief(previous)}")
            else:
                fields = sorted(set(current or {}) | set(previous or {}))
                before, after = previous or {}, current or {}
                changes = [
                    f"{f}: {visible(before.get(f), 80)} → {visible(after.get(f), 80)}"
                    for f in fields
                    if before.get(f) != after.get(f)
                ]
                text = Shown(f"changed: {visible(key)}: " + "; ".join(changes))
            shown.append({"when": "", "where": f"{section}, since the baseline", "text": text})
        elif "live" in ref and ref["live"][0] == "web_requests":
            requests = snapshot.live.get("web_requests") or {}
            shown.append(
                {
                    "when": "",
                    "where": "web requests, counted",
                    "text": _brief({"networks": len(requests.get("requests_by_network") or {})}),
                }
            )
        elif "live" in ref and ref["live"][0] == "mail_queues":
            for queue in snapshot.live.get("mail_queues", []):
                shown.append({"when": "", "where": "mail queue", "text": _brief(queue)})
        elif "live" in ref:
            _, pid = ref["live"]
            process = next(
                (p for p in snapshot.live.get("processes", []) if p.get("pid") == pid), None
            )
            keep = ("pid", "ppid", "comm", "exe", "cmdline", "uids", "start_time", "cwd")
            shown.append(
                {
                    "when": "",
                    "where": "running process",
                    "text": _brief({k: (process or {}).get(k) for k in keep}),
                }
            )
    more = len(finding.get("evidence", [])) - len(shown)
    if more > 0:
        shown.append({"when": "", "where": "", "text": f"… and {more} more"})
    return shown


def reassess(
    store: Store,
    row,
    recipients,
    assessment: dict,
    prior: tuple[float, str],
    whitelist: Whitelist | None,
    events: list,
) -> dict:
    """The assessment's findings with another whitelist or prior: the
    whitelist applied again, chains found again and the findings scored
    again, without running the checks (which could see another baseline by
    now). Stored as a new assessment; the earlier one is kept."""
    again = json.loads(json.dumps(assessment))
    again["analysed_at"] = datetime.now(UTC).isoformat()
    again["whitelist"] = reapply(again["findings"], whitelist, events=events)
    chains = find_chains(again["findings"], events, assessment.get("previous_time"))
    # Exposure to the packs' threats raised the prior when it was analysed:
    # the same raise, whatever the prior is now.
    raised_by = assessment["score"].get("raised_by") or []
    raised = prior_raise_of(raised_by)
    again["score"] = score(again["findings"], prior[0], chains, raised, raised_by) | {
        "prior_source": prior[1],
        "chains": chains,
    }
    again["counts"] = count(again["findings"])
    store_assessment(store, row, recipients, again)
    return again


def whitelist_hash(assessment: dict) -> str | None:
    return (assessment.get("whitelist") or {}).get("hash")


OLDER_CHECKS = "analysed by an older version of the checks"


def out_of_date(
    assessment: dict,
    prior: tuple[float, str] | None,
    whitelist: Whitelist | None = None,
    packs: list | None = None,
    pack_problems: list[str] | None = None,
    check_packs: bool = True,
    check_whitelist: bool = True,
) -> tuple[list[str], list[str]]:
    """Why a stored assessment isn't what a report would say now: what means
    analysing again, and what means only scoring again. The report acts on
    these and the fleet view shows them, so the two can't disagree. A prior
    of None, or a check turned off, isn't compared."""
    analyse, rescore = [], []
    # Its evidence points into one parse of the bundle (event numbers,
    # snapshot keys): any newer parser or checks means analysing again.
    if assessment.get("versions") != current_versions():
        analyse.append(OLDER_CHECKS)
    # So do other packs: what they judge and detect isn't in the findings.
    if check_packs and (
        assessment.get("packs", []) != packs_applied(packs)
        or assessment.get("packs_not_applied", []) != list(pack_problems or [])
    ):
        analyse.append("the threat packs in force have changed")
    if analyse:  # analysing again settles the rest; an old format has none of it
        return analyse, rescore
    if (
        prior is not None
        and (
            assessment["score"]["prior"],
            assessment["score"]["prior_source"],
        )
        != prior
    ):
        rescore.append("the host's starting probability has changed")
    if check_whitelist:
        if whitelist_hash(assessment) != (whitelist.digest() if whitelist else None):
            rescore.append("the whitelist has changed")
        # A rule that has expired since the assessment stops suppressing.
        elif whitelist and whitelist.expired() != assessment["whitelist"].get("expired"):
            rescore.append("a whitelist rule has expired")
    return analyse, rescore


def host_report(
    store: Store,
    host: str,
    identity,
    recipients,
    bundle_id=None,
    prior: tuple[float, str] = (DEFAULT_PRIOR, "default"),
    whitelist: Whitelist | None = None,
    packs: list | None = None,
    pack_problems: list[str] | None = None,
) -> HostReport:
    """A host's latest (or a given) bundle, analysed with the current
    checks, whitelist, prior and threat packs: analysed again if its stored
    assessment is missing or older or applied other packs, reassessed if
    only the whitelist or prior changed."""
    rows = usable_bundles(store, host)
    if bundle_id is None and not rows:
        raise EvidenceError(f"no usable bundle for {host}")
    row = store.bundle(bundle_id) if bundle_id else rows[-1]
    if row["host"] != host:
        raise EvidenceError(f"bundle {row['id']} is from {row['host']}, not {host}")
    if row["status"] not in USABLE:
        raise EvidenceError(f"bundle {row['id']} is {row['status']}: nothing to report")
    assessment = load_assessment(store, row["id"], identity)
    analyse, rescore = (
        out_of_date(assessment, prior, whitelist, packs, pack_problems)
        if assessment is not None
        else ([], [])
    )
    if assessment is None or analyse:
        assessment = analyze(
            store, host, identity, recipients, row["id"], prior, whitelist, packs, pack_problems
        )
    elif rescore:
        parsed = load_events(store, row, identity)
        events = parsed.events if parsed else events_of(store, row, identity, recipients)
        assessment = reassess(store, row, recipients, assessment, prior, whitelist, events)
    parsed = load_events(store, row, identity)
    events = parsed.events if parsed else events_of(store, row, identity, recipients)
    snapshot = snapshot_of(store, row, identity, recipients)
    baselines = {}
    for finding in assessment["findings"]:
        for ref in finding.get("evidence", []):
            against = (ref.get("change") or [None])[0]
            if against and against not in baselines:
                try:
                    baselines[against] = snapshot_of(
                        store, store.bundle(against), identity, recipients
                    )
                except EvidenceError:
                    baselines[against] = None  # gone: its excerpts show the current side only
    summary = json.loads(open_text(row["summary"], identity) or "{}")
    report = HostReport(
        host=host,
        row=row,
        assessment=assessment,
        manifest=summary.get("manifest") or {},
        custody=store.custody_of(row["id"]),
        events=events,
        snapshot=snapshot,
        baselines=baselines,
    )
    from checker.advisor.advise import latest_advice

    report.advice = latest_advice(store, host, identity, row["id"], assessment.get("analysed_at"))
    in_effect = []
    for number, finding in enumerate(assessment["findings"], 1):
        finding = dict(
            finding, number=number, excerpts=excerpts(finding, events, snapshot, baselines)
        )
        if finding.get("suppressed_by"):
            report.suppressed.append(finding)
            continue  # in the appendix, with its rule; not in the timeline
        report.findings.setdefault(finding["category"], []).append(finding)
        counts = report.counts.setdefault(finding["category"], dict.fromkeys(BANDS, 0))
        counts[finding["band"]] += 1
        in_effect.append(finding)
    order = {band: i for i, band in enumerate(BANDS)}
    for listed in report.findings.values():
        listed.sort(key=lambda f: order[f["band"]])  # a maintenance window moves a band
    report.timeline = timeline_of(in_effect, events, assessment)
    return report


def timeline_of(findings: list[dict], events: list, assessment: dict) -> list[dict]:
    """The logged events behind these findings, in order, with each threat pack's window."""
    timeline: dict[int, dict] = {}
    for finding in findings:
        for ref in finding.get("evidence", []):
            index = ref.get("event")
            if isinstance(index, int) and 0 <= index < len(events) and events[index].corrected:
                entry = timeline.setdefault(
                    index,
                    {
                        "when": events[index].corrected,
                        "type": events[index].type,
                        "text": visible(events[index].line, 200)
                        if events[index].line
                        else _brief(events[index].fields, 200),
                        "findings": [],
                    },
                )
                if finding["title"] not in entry["findings"]:
                    entry["findings"].append(finding["title"])
    ordered = sorted(timeline.values(), key=lambda e: e["when"])
    if len(ordered) > MAX_TIMELINE:
        # The earliest events are often the first signs: keep both ends.
        head, tail = ordered[: MAX_TIMELINE // 3], ordered[-(MAX_TIMELINE - MAX_TIMELINE // 3) :]
        gap = {
            "when": "",
            "type": "",
            "text": f"… {len(ordered) - len(head) - len(tail)} events not shown …",
            "findings": [],
            "after": head[-1]["when"],  # where it goes among the threat packs' marks
        }
        ordered = [*head, gap, *tail]
    return sorted([*ordered, *exposure_marks(assessment)], key=lambda e: e.get("after", e["when"]))


def exposure_marks(assessment: dict) -> list[dict]:
    """The timeline's marks for each threat pack's window and the host's
    exposure in it (the assessment's `exposures`, checker.assess)."""
    marks = []

    def mark(when, text):
        if when:
            marks.append({"when": when, "type": "threat pack", "text": text, "findings": []})

    for item in (assessment.get("exposures") or [])[:MAX_MARKED]:
        named = f"{visible(item.get('pack'), 80)} v{visible(item.get('version'), 10)}"
        if not item.get("share"):
            continue  # never exposed: the window says nothing about this host
        mark(item.get("window_start"), f"{named}: the threat's window opens")
        mark(item.get("window_end"), f"{named}: the threat's window closes")
        if not item.get("judged", True):
            continue  # counted as exposed for want of a full listing: no dates of its own
        if item.get("exposed_from") != item.get("window_start"):
            mark(item.get("exposed_from"), f"{named}: the host is exposed from here")
        until = item.get("exposed_until")
        if until and until != item.get("window_end"):
            exact = item.get("fix_time_exact")
            mark(until, f"{named}: exposed until here" + ("" if exact else " at the latest"))
    return marks


def render(
    reports: list[HostReport], generated_by: tuple[str, str], advisor_enabled: bool = False
) -> str:
    environment = Environment(
        loader=PackageLoader("checker", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
        finalize=_finalize,
    )
    environment.filters["visible"] = visible
    environment.filters["percent"] = percent
    template = environment.get_template("report.html.j2")
    return template.render(
        reports=reports,
        bands=BANDS,
        categories=CATEGORIES,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        operator=generated_by[0],
        controller=generated_by[1],
        version=__version__,
        checks_version=CHECKS_VERSION,
        advisor_enabled=advisor_enabled,
    )


def write_report(
    store: Store,
    hosts: list[str],
    identity: x25519.Identity,
    recipients: list[str],
    directory: Path,
    bundle_id: str | None = None,
    output: Path | None = None,
    priors: Callable[[str], tuple[float, str]] | None = None,
    whitelists: Callable[[str], Whitelist | None] | None = None,
    advisor_enabled: bool = False,
    plain: bool = False,
    packs: Callable[[str], tuple[list, list[str]]] | None = None,
) -> Path:
    """Write the report, encrypted to the evidence key (`report-….html.age`;
    read_report() reads it) unless `plain`, owner-only either way, and add
    a `reported` entry, with the hash of the file as written, to each
    bundle's custody. `packs` gives a host's threat packs and why any
    isn't applied (checker.packs.choice.for_host)."""
    if output is not None and not plain and not output.name.endswith(".html.age"):
        raise EvidenceError(
            f"an encrypted report's name ends in .html.age ({output.name}); --plain writes"
            " plain HTML"
        )
    if output is not None and plain and output.suffix == ".age":
        raise EvidenceError(f"a plain report's name can't end in .age ({output.name})")
    priors = priors or (lambda _: (DEFAULT_PRIOR, "default"))
    whitelists = whitelists or (lambda _: None)
    packs = packs or (lambda _: ([], []))
    reports = [
        host_report(store, h, identity, recipients, bundle_id, priors(h), whitelists(h), *packs(h))
        for h in hosts
    ]
    html = render(reports, who_and_where(), advisor_enabled)
    if output is None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)  # also when it was already there
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        name = hosts[0] if len(hosts) == 1 else f"{len(hosts)}-hosts"
        output = directory / (f"report-{name}-{stamp}.html" + ("" if plain else ".age"))
    data = html.encode("utf-8", "backslashreplace")  # never fails on stray text
    if not plain:
        data = pyrage.encrypt(data, [x25519.Recipient.from_str(r) for r in recipients])
    # Written whole beside its place (mkstemp makes it owner-only) and then
    # moved there: a crash leaves the old file, a link at the path is
    # replaced rather than followed, and no one holding the old file open
    # can read the new.
    fd, partial = tempfile.mkstemp(dir=output.parent, prefix=".report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(partial, output)
    except BaseException:
        Path(partial).unlink(missing_ok=True)
        raise
    digest = hashlib.sha256(data).hexdigest()
    for report in reports:
        store.custody(
            report.row["id"], "reported", {"report_sha256": digest, "encrypted": not plain}
        )
    return output


def read_report(path: Path, identity: x25519.Identity | None) -> str:
    """A report's HTML: decrypted when it was written encrypted (.age). The
    one way in for anything that shows reports."""
    data = path.read_bytes()
    if path.suffix == ".age":
        if identity is None:
            raise EvidenceError("no evidence key here; pass --identity PATH")
        try:
            data = pyrage.decrypt(data, [identity])
        except pyrage.DecryptError as exc:
            raise EvidenceError(f"cannot decrypt {path.name}: {exc}") from None
    return data.decode("utf-8")


def latest_report(directory: Path) -> Path | None:
    """The newest report in the reports folder, encrypted or plain (by time,
    then by name, whose UTC stamp sorts by time where clocks are coarse)."""
    found = [
        p
        for p in directory.glob("report-*.html*")
        if p.name.endswith((".html", ".html.age")) and p.is_file() and not p.is_symlink()
    ]
    return _newest(found)


def _newest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: (p.stat().st_mtime, p.name)) if paths else None


# The page's own policy, sent as a header too: it loads nothing.
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none';"
    " base-uri 'none'"
)
NO_TERMINAL_SECONDS = 600  # how long a report is shown with no terminal to press Enter in


def has_screen(environ: dict[str, str] | None = None, platform: str | None = None) -> bool:
    """Whether a graphical browser can be started here (not over SSH)."""
    environ = os.environ if environ is None else environ
    if (platform or sys.platform) == "darwin":
        return not environ.get("SSH_CONNECTION")
    return bool(environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY"))


def _launch(url: str) -> bool:
    try:
        browser = webbrowser.get()
    except webbrowser.Error:
        return False
    if isinstance(browser, webbrowser.GenericBrowser) and not isinstance(
        browser, webbrowser.BackgroundBrowser
    ):  # a text browser (lynx, w3m, $BROWSER): it would take the terminal
        return False
    return browser.open(url)


def view(
    path: Path,
    identity: x25519.Identity | None,
    browser: Callable[[str], bool] | None = None,
    ask: Callable[[str], str] = input,
    wait: Callable[[float], None] | None = None,
    say: Callable[[str], None] = print,
    screen: bool | None = None,
) -> None:
    """Show a report in the browser without writing it anywhere in plain. It
    is served from memory on 127.0.0.1, at an address no one can guess (a
    random port and a long random path), to requests naming that address
    as their host, never to be cached; until Enter is pressed, or, with no
    terminal, for ten minutes. Sandboxed browsers (snap, Flatpak), which
    can't read a private file, can read it; over SSH, it says how to see it
    through a forwarded port."""
    body = read_report(path, identity).encode("utf-8")
    route = f"/{secrets.token_urlsafe(32)}/{path.name.removesuffix('.age')}"

    class Show(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the library's name
            port = self.server.server_address[1]
            if self.path != route or self.headers.get("Host") != f"127.0.0.1:{port}":
                self.send_error(404)
                return
            self.send_response(200)
            for name, value in (
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("Content-Security-Policy", CSP),
                ("Referrer-Policy", "no-referrer"),
                ("X-Content-Type-Options", "nosniff"),
            ):
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:  # nothing on the terminal per request
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Show)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}{route}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        if (has_screen() if screen is None else screen) and (browser or _launch)(url):
            say(f"Showing {path.name} in your browser, from memory: nothing is written in plain.")
        else:
            say(
                f"Showing {path.name} at {url}\n"
                f"From another machine: ssh -L {port}:127.0.0.1:{port} THIS-HOST, then open"
                " that address there."
            )
        try:
            ask("Press Enter to stop showing it: ")
        except EOFError:
            minutes = NO_TERMINAL_SECONDS // 60
            say(f"No terminal to press Enter in: it is shown for {minutes} minutes.")
            (wait or time.sleep)(NO_TERMINAL_SECONDS)
    finally:
        server.shutdown()
        server.server_close()

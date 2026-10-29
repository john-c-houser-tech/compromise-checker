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
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup
from pyrage import x25519

from checker import __version__
from checker.analysis import load_events, snapshot_of
from checker.assess import analyze, count, events_of, load_assessment, store_assessment
from checker.baseline import USABLE, usable_bundles
from checker.checks import BANDS, CATEGORIES, CHECKS_VERSION
from checker.correlate import find_chains
from checker.evidence import EvidenceError, Store, open_text, who_and_where
from checker.scoring import DEFAULT_PRIOR, percent, score
from checker.snapshot import Snapshot
from checker.whitelist import Whitelist, reapply

MAX_EVIDENCE = 5  # excerpts shown per finding
MAX_TIMELINE = 300
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
    # What the findings' evidence points into, for the advisor's case file.
    events: list = field(default_factory=list)
    snapshot: Snapshot | None = None
    baselines: dict[str, Snapshot | None] = field(default_factory=dict)


def excerpts(
    finding: dict, events, snapshot: Snapshot, baselines: dict[str, Snapshot]
) -> list[dict]:
    """What each piece of a finding's evidence says, briefly."""
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
    again["score"] = score(again["findings"], prior[0], chains) | {
        "prior_source": prior[1],
        "chains": chains,
    }
    again["counts"] = count(again["findings"])
    store_assessment(store, row, recipients, again)
    return again


def whitelist_hash(assessment: dict) -> str | None:
    return (assessment.get("whitelist") or {}).get("hash")


def host_report(
    store: Store,
    host: str,
    identity,
    recipients,
    bundle_id=None,
    prior: tuple[float, str] = (DEFAULT_PRIOR, "default"),
    whitelist: Whitelist | None = None,
) -> HostReport:
    """A host's latest (or a given) bundle, analysed with the current
    checks, whitelist and prior: analysed again if its stored assessment is
    missing or older, reassessed if only the whitelist or prior changed."""
    rows = usable_bundles(store, host)
    if bundle_id is None and not rows:
        raise EvidenceError(f"no usable bundle for {host}")
    row = store.bundle(bundle_id) if bundle_id else rows[-1]
    if row["host"] != host:
        raise EvidenceError(f"bundle {row['id']} is from {row['host']}, not {host}")
    if row["status"] not in USABLE:
        raise EvidenceError(f"bundle {row['id']} is {row['status']}: nothing to report")
    assessment = load_assessment(store, row["id"], identity)
    # Its evidence points into one parse of the bundle (event numbers,
    # snapshot keys): any newer parser or checks means analysing again.
    if assessment is None or assessment.get("versions") != current_versions():
        assessment = analyze(store, host, identity, recipients, row["id"], prior, whitelist)
    elif (
        (assessment["score"]["prior"], assessment["score"]["prior_source"]) != prior
        or whitelist_hash(assessment) != (whitelist.digest() if whitelist else None)
        # A rule that has expired since the assessment stops suppressing.
        or (whitelist and whitelist.expired() != assessment["whitelist"].get("expired"))
    ):
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
    timeline = {}
    for finding in assessment["findings"]:
        finding = dict(finding, excerpts=excerpts(finding, events, snapshot, baselines))
        if finding.get("suppressed_by"):
            report.suppressed.append(finding)
            continue  # in the appendix, with its rule; not in the timeline
        report.findings.setdefault(finding["category"], []).append(finding)
        counts = report.counts.setdefault(finding["category"], dict.fromkeys(BANDS, 0))
        counts[finding["band"]] += 1
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
    order = {band: i for i, band in enumerate(BANDS)}
    for listed in report.findings.values():
        listed.sort(key=lambda f: order[f["band"]])  # a maintenance window moves a band
    ordered = sorted(timeline.values(), key=lambda e: e["when"])
    if len(ordered) > MAX_TIMELINE:
        # The earliest events are often the first signs: keep both ends.
        head, tail = ordered[: MAX_TIMELINE // 3], ordered[-(MAX_TIMELINE - MAX_TIMELINE // 3) :]
        gap = {
            "when": "",
            "type": "",
            "text": f"… {len(ordered) - len(head) - len(tail)} events not shown …",
            "findings": [],
        }
        ordered = [*head, gap, *tail]
    report.timeline = ordered
    return report


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
) -> Path:
    """Write the report (owner-only, like the evidence) and add a
    `reported` entry, with the report's hash, to each bundle's custody."""
    priors = priors or (lambda _: (DEFAULT_PRIOR, "default"))
    whitelists = whitelists or (lambda _: None)
    reports = [
        host_report(store, h, identity, recipients, bundle_id, priors(h), whitelists(h))
        for h in hosts
    ]
    html = render(reports, who_and_where(), advisor_enabled)
    if output is None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)  # also when it was already there
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        name = hosts[0] if len(hosts) == 1 else f"{len(hosts)}-hosts"
        output = directory / f"report-{name}-{stamp}.html"
    data = html.encode("utf-8", "backslashreplace")  # never fails on stray text
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
        store.custody(report.row["id"], "reported", {"report_sha256": digest})
    return output

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
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from pyrage import x25519

from checker import __version__
from checker.analysis import load_events, snapshot_of
from checker.assess import analyze, events_of, load_assessment
from checker.baseline import usable_bundles
from checker.checks import BANDS, CATEGORIES, CHECKS_VERSION
from checker.evidence import EvidenceError, Store, open_text, who_and_where
from checker.snapshot import Snapshot

MAX_EVIDENCE = 5  # excerpts shown per finding
MAX_TIMELINE = 300
MAX_TEXT = 300


def visible(value: Any, limit: int = MAX_TEXT) -> str:
    """Host text made safe to show: control, format (bidirectional
    overrides, zero-width) and other invisible characters become escapes
    like \\u202e; long text is cut."""
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    out = []
    for char in text[: limit + 1]:
        if unicodedata.category(char) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp") and char != " ":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    shown = "".join(out)
    return shown if len(text) <= limit else shown[:limit] + "…"


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
    timeline: list[dict] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)


def _excerpts(
    finding: dict, events, snapshot: Snapshot, baselines: dict[str, Snapshot]
) -> list[dict]:
    """What each piece of a finding's evidence says, briefly."""
    shown = []
    for ref in finding.get("evidence", [])[:MAX_EVIDENCE]:
        if "event" in ref and 0 <= ref["event"] < len(events):
            event = events[ref["event"]]
            shown.append(
                {
                    "when": event.corrected or event.time or "",
                    "where": visible(event.source, 80),
                    "text": visible(event.line or f"{event.type} {_brief(event.fields)}"),
                }
            )
        elif "item" in ref:
            section, key = ref["item"]
            item = (
                snapshot.sections.get(section).items if section in snapshot.sections else {}
            ).get(key)
            shown.append({"when": "", "where": section, "text": f"{visible(key)}: {_brief(item)}"})
        elif "change" in ref:
            against, section, key, how = ref["change"]
            now = snapshot.sections.get(section)
            current = (now.items if now else {}).get(key)
            before_snapshot = baselines.get(against)
            then = before_snapshot.sections.get(section) if before_snapshot else None
            previous = (then.items if then else {}).get(key)
            if how == "added":
                text = f"added: {visible(key)}: {_brief(current)}"
            elif how == "removed":
                text = f"removed: {visible(key)}: {_brief(previous)}"
            else:
                fields = sorted(set(current or {}) | set(previous or {}))
                before, after = previous or {}, current or {}
                changes = [
                    f"{f}: {visible(before.get(f), 80)} → {visible(after.get(f), 80)}"
                    for f in fields
                    if before.get(f) != after.get(f)
                ]
                text = f"changed: {visible(key)}: " + "; ".join(changes)
            shown.append({"when": "", "where": f"{section}, since the baseline", "text": text})
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


def host_report(store: Store, host: str, identity, recipients, bundle_id=None) -> HostReport:
    """A host's latest (or a given) bundle, analysed with the current
    checks if its stored assessment is missing or older."""
    rows = usable_bundles(store, host)
    if bundle_id is None and not rows:
        raise EvidenceError(f"no usable bundle for {host}")
    row = store.bundle(bundle_id) if bundle_id else rows[-1]
    assessment = load_assessment(store, row["id"], identity)
    if assessment is None or assessment.get("checks_version") != CHECKS_VERSION:
        assessment = analyze(store, host, identity, recipients, row["id"])
    parsed = load_events(store, row, identity)
    events = parsed.events if parsed else events_of(store, row, identity, recipients)
    snapshot = snapshot_of(store, row, identity, recipients)
    baselines = {}
    for finding in assessment["findings"]:
        for ref in finding.get("evidence", []):
            against = (ref.get("change") or [None])[0]
            if against and against not in baselines:
                baselines[against] = snapshot_of(store, store.bundle(against), identity, recipients)
    summary = json.loads(open_text(row["summary"], identity) or "{}")
    report = HostReport(
        host=host,
        row=row,
        assessment=assessment,
        manifest=summary.get("manifest") or {},
        custody=store.custody_of(row["id"]),
    )
    timeline = {}
    for finding in assessment["findings"]:
        finding = dict(finding, excerpts=_excerpts(finding, events, snapshot, baselines))
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
                        "text": visible(events[index].line or _brief(events[index].fields), 200),
                        "findings": [],
                    },
                )
                if finding["title"] not in entry["findings"]:
                    entry["findings"].append(finding["title"])
    report.timeline = sorted(timeline.values(), key=lambda e: e["when"])[-MAX_TIMELINE:]
    return report


def render(reports: list[HostReport], generated_by: tuple[str, str]) -> str:
    environment = Environment(
        loader=PackageLoader("checker", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["visible"] = visible
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
    )


def write_report(
    store: Store,
    hosts: list[str],
    identity: x25519.Identity,
    recipients: list[str],
    directory: Path,
    bundle_id: str | None = None,
    output: Path | None = None,
) -> Path:
    """Write the report (owner-only, like the evidence) and add a
    `reported` entry, with the report's hash, to each bundle's custody."""
    reports = [host_report(store, h, identity, recipients, bundle_id) for h in hosts]
    html = render(reports, who_and_where())
    if output is None:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        name = hosts[0] if len(hosts) == 1 else f"{len(hosts)}-hosts"
        output = directory / f"report-{name}-{stamp}.html"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(html)
    os.chmod(output, 0o600)
    digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
    for report in reports:
        store.custody(report.row["id"], "reported", {"report_sha256": digest})
    return output

"""What the fleet means, in words for someone who has never read a log. The tool's own
results stay exact in checker.fleet; this says them plainly and says what to do.

The rule that matters: green has to be earned. A server reads "no strong signs" only if
its score is Low and nothing in `_cautions` has anything to say. Anything new the fleet
learns to report belongs there, not in a note beside a reassuring result."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from checker.fleet import UNREADABLE, FleetHost, serious, sort_key
from checker.report import OLDER_CHECKS, visible
from checker.schedule import SERIOUS
from checker.web.finding_words import BAND_WORDS, SECTIONS, gap_words, words_for

# How worrying each band is, for colour and for what the page leads with.
VERDICTS = {
    "Critical": ("critical", "Strong signs of a break-in", "Act on this now."),
    "High": ("high", "Signs of a break-in", "Look into this today."),
    "Elevated": ("elevated", "Some warning signs", "Look into this soon."),
    "Low": ("low", "No strong signs of a break-in", ""),
}
NOT_ANALYSED = {
    "not_analysed": ("Nothing to go on yet", "Its results haven't been worked out: run a check."),
    "no_evidence": ("Nothing to go on yet", "Run its first check."),
    "collections_failed": (
        "Nothing to go on yet",
        "Every check has failed so far: find out why it can't reach this server.",
    ),
    "purged": ("Nothing known now", "Its old results were deleted: run a fresh check."),
}
TONE_NAMES = {
    "critical": "Strong signs",
    "high": "Signs of a break-in",
    "unknown": "Need a closer look",
    "elevated": "Warning signs",
    "low": "No strong signs",
    "removed": "No longer checked",
}
FRESH_CHECK = "Run a fresh check."
ASK_WHY = "Ask whoever runs this server why."
SETTINGS_CHANGED = "Settings have changed since this result, so it may change at the next check."
NEW_THREAT = "New threat information has arrived, and this server hasn't been checked against it."
LOGS_MISSING = " Logs can go missing when someone covers their tracks."

# The tool's reasons for doubt, by how they start: what a reader should hear, and whether
# time alone can explain it (a fresh check may clear it, and a result "may have changed").
DOUBTS = (
    ("its last collection was", "The last check didn't finish.", True),
    ("this collection was", "The last check only saw part of this server.", True),
    ("a newer collection", "A newer check hasn't been worked out yet.", True),
    ("collected more than", "This server hasn't been checked recently.", True),
    ("checks that couldn't run", "Some of the checks couldn't run.", False),
    ("it can see less than before", "The check can see less of this server than before.", False),
    ("part of this server", "Part of this server couldn't be read.", False),
    ("no authentication log events", f"No record of logins can be seen.{LOGS_MISSING}", False),
    ("no system journal events", f"The system's own log can't be seen.{LOGS_MISSING}", False),
    ("the whitelist", SETTINGS_CHANGED, True),
    ("a whitelist rule", SETTINGS_CHANGED, True),
    ("its whitelist", "Its list of accepted activity can't be read.", False),
    ("the threat packs", NEW_THREAT, True),
    ("the host's starting", SETTINGS_CHANGED, True),
    ("part of its analysis", "Part of this result couldn't be worked out.", False),
)
EXPOSURE_WORDS = {
    "fixed": "Was open to a known threat while it was active, and is fixed now: {}.",
    "can't judge": "May be open to a known threat, and the check can't tell: {}.",
    "vulnerable": "Open to a known threat now: {}.",
}
_BAND_MOVE = re.compile(r"(Low|Elevated|High|Critical) to (Low|Elevated|High|Critical)\b")
_NEW = re.compile(r"new \w+: ")
_NOW = re.compile(r"now \w+ \(was \w+\): ")


@dataclass(frozen=True)
class Row:
    """One server, as the page shows it."""

    host: FleetHost
    tone: str
    verdict: str
    action: str
    notes: tuple[str, ...]
    changes: tuple[str, ...]
    exposures: tuple[str, ...]
    checked: str


@dataclass(frozen=True)
class _Caution:
    """Something that keeps a Low result from being green: what to call the server then
    (the first caution found wins), and what to do."""

    verdict: str
    action: str


def _doubt(doubt: str) -> tuple[str, bool]:
    for start, words, by_time in DOUBTS:
        if doubt.startswith(start):
            if start == "it can see less than before" and re.search("log|journal", doubt):
                words += LOGS_MISSING  # only where it is logs that went missing
            return words, by_time
    return doubt, False


def plain_doubt(doubt: str) -> str:
    return _doubt(doubt)[0]


def ago(moment: str | None, now: datetime) -> str:
    if not moment:
        return ""
    try:
        seconds = (now - datetime.fromisoformat(moment)).total_seconds()
    except (TypeError, ValueError):
        return ""
    if seconds < -3600:
        return ""  # a date in the future says nothing about when it was checked
    if seconds < 3600:
        return "Checked within the last hour"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"Checked {hours} hour{'s' if hours != 1 else ''} ago"
    days = int(seconds // 86400)
    return f"Checked {days} day{'s' if days != 1 else ''} ago"


def _change(line: str, host: str) -> str | None:
    """A line of alerts() for the list of what's new, or None if it is said elsewhere on
    the row: the move between bands, or an exposure to a threat."""
    what = line.removeprefix(f"{host}: ")
    if _BAND_MOVE.match(what) or what.startswith("exposed to threat pack "):
        return None
    if what.startswith("check ") and what.endswith(" failed"):
        return None  # "some of the checks couldn't run" says it
    if found := _NEW.match(what):
        return what[found.end() :]
    if found := _NOW.match(what):
        return f"{what[found.end() :]} (now more serious)"
    return what.removeprefix("newly weighed by a threat pack: ")


def _cautions(host: FleetHost) -> tuple[list[_Caution], list[str]]:
    """Everything that keeps this server from reading as fine, most telling first, and
    the notes that say why. A High or Critical server shows the notes too."""
    cautions: list[_Caution] = []
    notes: list[str] = []
    exposed = host.exposed
    if "vulnerable" in exposed.values():
        cautions.append(_Caution("Open to a known threat", "Update this server."))
    if "can't judge" in exposed.values():
        cautions.append(
            _Caution(
                "May be open to a known threat",
                "Ask whoever runs this server which version it runs.",
            )
        )
    if host.stale_code:
        cautions.append(
            _Caution(
                "Still running code from before a fix",
                "Restart its services, unless a break-in is suspected: then get advice first.",
            )
        )
        notes.append(
            "A fix is installed, but something on this server is still running the old code."
        )
    if host.unjudged:
        notes.append(
            f"The check couldn't tell whether this server is open to: {', '.join(host.unjudged)}."
        )
        cautions.append(_Caution("Can't tell if it's open to a known threat", FRESH_CHECK))
    if serious(host) or host.hygiene in SERIOUS:
        count = serious(host)
        words = f"{count} serious problem{'s' if count != 1 else ''} found." if count else ""
        notes.append(words or "Serious weaknesses found.")
        cautions.append(
            _Caution(
                "Serious problems found, even though the estimate is low", "Look into this soon."
            )
        )
    if host.threat_signs:
        cautions.append(_Caution("A sign of a known threat was found", "Look into this today."))
    worse = ("Elevated", "High", "Critical")
    earlier = host.band_before in worse or host.rescored_from in worse
    if earlier or host.not_seen or host.suppressed or host.resolved:
        cautions.append(
            _Caution("No strong signs now, but there were last time", "Find out what changed.")
        )
    if host.rescored_from:
        notes.append(_said("This same check first showed", host.rescored_from))
    elif host.band_before and host.band_before != host.band:
        notes.append(_said("The check before showed", host.band_before))
    if host.not_seen:
        notes.append(
            f"{_warnings(host.not_seen)} from before weren't seen this time, which doesn't mean"
            " they've gone."
        )
    if host.suppressed:
        notes.append(f"{_warnings(host.suppressed)} now hidden by your list of accepted activity.")
    if host.resolved:
        notes.append(
            f"{_warnings(host.resolved)} from before no longer found. Someone removing what they"
            " left behind looks the same, so find out what changed."
        )
    if host.before_unreadable:
        notes.append("The result before this one can't be read, so changes can't be shown.")
        cautions.append(_Caution("No strong signs, but its history can't be read", ASK_WHY))
    blind = [d for d in host.doubts if d.startswith(("no authentication", "no system journal"))]
    if blind:
        cautions.append(_Caution("The check can't see this server's logs", ASK_WHY))
    for doubt in host.doubts:
        words, by_time = _doubt(doubt)
        notes.append(words)
        if doubt.startswith("the threat packs"):
            cautions.append(_Caution("Not checked against new threat information", FRESH_CHECK))
        elif by_time:
            cautions.append(_Caution("No strong signs, but don't rely on this yet", FRESH_CHECK))
        else:
            cautions.append(_Caution("No strong signs, but don't rely on this yet", ASK_WHY))
    return cautions, list(dict.fromkeys(notes))


def _said(start: str, band: object) -> str:
    verdict = VERDICTS.get(band) if isinstance(band, str) else None
    return f"{start}: {(verdict[1] if verdict else 'no score').lower()}."


def _warnings(n: int) -> str:
    return f"{n} serious warning{'s' if n != 1 else ''}"


def _only_by_time(host: FleetHost) -> bool:
    return bool(host.doubts) and all(_doubt(d)[1] for d in host.doubts)


def _row(host: FleetHost, now: datetime) -> Row:
    cautions, notes = _cautions(host)
    if host.state == "unreadable":
        tone, verdict = "critical", "This result can't be read"
        action = "Find out why before trusting anything about this server."
        why = UNREADABLE.get(host.unreadable_why or "internal", UNREADABLE["internal"])
        notes.insert(0, f"{why[0].upper()}{why[1:]}.")
        if host.last_readable_band:
            notes.append(
                _said("The last result that could be read showed", host.last_readable_band)
            )
    elif host.state != "analysed":
        tone = "unknown"
        verdict, action = NOT_ANALYSED.get(host.state, ("Nothing to go on yet", FRESH_CHECK))
    else:
        tone, verdict, action = VERDICTS.get(host.band, ("unknown", "No score", FRESH_CHECK))
        if tone == "low" and cautions:
            tone, verdict, action = "unknown", cautions[0].verdict, cautions[0].action
        elif tone in ("critical", "high", "elevated") and _only_by_time(host):
            action = f"{action} This result may have changed since."
        if host.probability is None and tone == "low":
            tone, verdict, action = "unknown", "No score", FRESH_CHECK
    if host.removed:
        notes.append("No longer on your list of servers, so it isn't being checked.")
        if tone in ("low", "unknown"):
            tone, action = "removed", "Remove its stored results if you don't need them."
            verdict = "No longer being checked"
    if host.last_failed and host.state != "collections_failed":
        notes.append("The last check didn't finish.")
    if host.gaps and host.state == "analysed":
        count = f"{host.gaps} thing{'s' if host.gaps != 1 else ''}"
        notes.append(f"{count} couldn't be checked on this server.")
    if host.first and host.state == "analysed":
        notes.append("This is its first check, so changes will show from the next one.")
    if OLDER_CHECKS in host.out_of_date:
        notes.append("Worked out by an older version of this tool.")
    changes = tuple(dict.fromkeys(c for c in (_change(x, host.host) for x in host.changes) if c))
    # While old code still runs, "fixed" isn't the whole story: a note above says so.
    exposures = tuple(
        EXPOSURE_WORDS[how].format(pack).replace(", and is fixed now", ", and has a fix installed")
        if host.stale_code
        else EXPOSURE_WORDS[how].format(pack)
        for pack, how in sorted(host.exposed.items())
        if how in EXPOSURE_WORDS
    )
    return Row(
        host,
        tone,
        verdict,
        action,
        tuple(dict.fromkeys(notes)),
        changes,
        exposures,
        ago(host.collected_at, now),
    )


def row(host: FleetHost, now: datetime | None = None) -> Row:
    """One server's row. Odd stored data makes it loud, and never takes the page down."""
    now = now or datetime.now(UTC)
    try:
        return _row(host, now)
    except Exception:  # noqa: BLE001 - one host's data mustn't hide the rest of the fleet
        return _row(
            FleetHost(host.host, state="unreadable", unreadable_why="internal"),
            now,
        )


def headline(rows: list[Row]) -> tuple[str, str]:
    """The answer the page opens with, from the most worrying thing on it, and its tone.
    Servers no longer on the list count only if they're alarming: they aren't "yours"
    to reassure about."""
    current = [r for r in rows if r.tone != "removed"]
    total = len(current)
    if not total:
        return ("No servers being checked." if rows else "No servers yet."), "unknown"

    def count(*tones: str) -> int:
        return sum(1 for r in current if r.tone in tones)

    def of(n: int) -> str:
        return "Your server" if total == 1 else f"{n} of your {total} servers"

    def verb(n: int, one: str, many: str) -> str:
        return one if n == 1 or total == 1 else many

    urgent = count("critical", "high")
    if urgent:
        return f"{of(urgent)} {verb(urgent, 'needs', 'need')} attention now.", "critical"
    unknown = count("unknown")
    if unknown:
        return f"{of(unknown)} {verb(unknown, 'needs', 'need')} a closer look.", "unknown"
    elevated = count("elevated")
    if elevated:
        return f"{of(elevated)} {verb(elevated, 'has', 'have')} some warning signs.", "elevated"
    where = "your server" if total == 1 else f"your {total} servers"
    return f"No strong signs of a break-in on {where}.", "low"


def rows_for(hosts: list[FleetHost], now: datetime | None = None) -> list[Row]:
    return [row(h, now) for h in sorted(hosts, key=sort_key)]


def host_details(assessment: dict | None) -> dict:
    """A host page's findings in plain words, most serious first and split as the report
    splits them. Odd stored data leaves things out of the sections, never the page down."""
    empty = {"sections": [], "suppressed": [], "gaps": [], "reach": None, "caveat": None}
    if not isinstance(assessment, dict):
        return empty
    try:
        return _host_details(assessment)
    except Exception:  # noqa: BLE001 - as for a row: the verdict above still shows
        return {**empty, "caveat": "Part of this result couldn't be worked out."}


def _host_details(assessment: dict) -> dict:
    findings = assessment.get("findings")
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
    in_effect = [f for f in findings if not f.get("suppressed_by")]
    hidden = [_finding(f) for f in findings if f.get("suppressed_by")]
    # Anything in a category not known here still shows, under its own heading.
    titles = [*SECTIONS.items(), (None, "Other findings")]
    sections = []
    for category, title in titles:
        here = [
            f
            for f in in_effect
            if (f.get("category") == category if category else f.get("category") not in SECTIONS)
        ]
        # A threat pack raising one means it's no longer for information only.
        folded = [
            _finding(f) for f in here if f.get("band") == "info" and not f.get("raised_by_pack")
        ]
        shown = [_finding(f) for f in here if f.get("band") != "info" or f.get("raised_by_pack")]
        shown.sort(key=lambda f: (not f["raised_by"], _BAND_ORDER.get(f["band_class"], 9)))
        if shown or folded:
            sections.append({"title": title, "findings": shown, "minor": folded})
    coverage = assessment.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    gaps = coverage.get("gaps")
    if not any(section["findings"] for section in sections):
        caveat = "No warnings on this check. That doesn't prove nothing happened."
        if hidden:
            caveat = f"No warnings in effect: {len(hidden)} hidden by your list, below."
    else:
        caveat = None
    return {
        "sections": sections,
        "suppressed": hidden,
        "gaps": list(dict.fromkeys(gap_words(g) for g in gaps)) if isinstance(gaps, list) else [],
        "reach": _log_reach(coverage.get("log_reach")),
        "caveat": caveat,
    }


_BAND_ORDER = {band: n for n, band in enumerate(BAND_WORDS)}


def _finding(finding: dict) -> dict:
    meaning, todo = words_for(finding.get("check"), finding.get("variant"), finding.get("title"))
    band = finding.get("band")
    known = isinstance(band, str) and band in BAND_WORDS
    raised = finding.get("raised_by_pack")
    return {
        "meaning": meaning,
        "todo": todo,
        "band_class": band if known else "medium",
        "band_words": BAND_WORDS[band] if known else "Worth a look",
        "new": bool(finding.get("new")),
        "title": finding.get("title"),
        "summary": finding.get("summary"),
        "uncertain": finding.get("uncertain"),
        "raised_by": raised,
        "lowered": bool(finding.get("maintenance")),
    }


def _log_reach(reach: object) -> str | None:
    """How far back the login logs go, said plainly: the shorter it is, the more it matters.
    The dates come from the logs themselves, so this says what they show, nothing more."""
    if not isinstance(reach, dict):
        return None
    days = [
        r.get("days")
        for name, r in reach.items()
        if name in ("auth_log", "auth_journal") and isinstance(r, dict)
    ]
    days = [d for d in days if isinstance(d, (int, float)) and not isinstance(d, bool)]
    days = [d for d in days if math.isfinite(d)]
    if not days:
        return None
    furthest = max(days)
    if furthest < 1:
        return (
            "Its login logs go back less than a day, so anything earlier can't be seen."
            " Logs this short can mean they were cleared."
        )
    return f"Its login logs go back {int(furthest)} days. Anything earlier can't be seen."


def evidence_details(stored: dict) -> dict:
    """The evidence page's contents. Parts that can't be worked out or weren't stored are
    said to be missing: the rest of the page still shows."""
    from checker.report import current_versions, excerpts, timeline_of
    from checker.snapshot import Snapshot

    empty = {
        "notes": [],
        "findings": [],
        "information": [],
        "timeline": [],
        "suppressed": [],
        "bundle": None,
        "custody": [],
        "collected_at": None,
    }
    assessment = stored.get("assessment")
    if not isinstance(assessment, dict):
        return {
            **empty,
            "notes": ["There's no readable result for this server to show evidence for."],
        }
    row = stored.get("row") or {}
    events = stored.get("events")
    snapshot = stored.get("snapshot")
    baselines = stored.get("baselines") or {}
    notes = []
    if assessment.get("versions") != current_versions():
        # Its evidence points into one parse: another parse's line 12 is a different line.
        events, snapshot, baselines = None, None, {}
        notes.append(
            "This result was worked out by an older version of this tool, so its excerpts and"
            " order of events can't be matched up. The next check shows them."
        )
    elif events is None or snapshot is None:
        notes.append(
            "Some of this check's details aren't stored or can't be read, so some excerpts are"
            " missing. The next check stores them again."
        )
    if any(found is None for found in baselines.values()):
        notes.append(
            'An earlier check these findings compare with is gone or can\'t be read, so "before"'
            " values may show as blank when they weren't."
        )
    findings = assessment.get("findings")
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
    in_effect = [f for f in findings if not f.get("suppressed_by")]
    listed = [f for f in in_effect if f.get("band") != "info" or f.get("raised_by_pack")]
    listed.sort(
        key=lambda f: _BAND_ORDER.get(f.get("band"), 9) if isinstance(f.get("band"), str) else 9
    )
    shown = []
    for finding in listed:
        shown.append(_with_excerpts(finding, events or [], snapshot, baselines, excerpts, Snapshot))
    try:
        timeline = timeline_of(in_effect, events or [], assessment)
    except Exception:  # noqa: BLE001 - as above
        timeline, notes = [], [*notes, "The order of events couldn't be worked out."]
    if (
        events
        and any(_event_refs(f) for f in in_effect)
        and not any(e.get("type") != "threat pack" for e in timeline)
    ):
        notes.append("The order of events can't be shown: those log lines have no usable time.")
    suppressed = []
    for finding in findings:
        by = finding.get("suppressed_by")
        if by:
            by = by if isinstance(by, dict) else {}
            suppressed.append(
                {
                    "title": finding.get("title"),
                    "summary": finding.get("summary"),
                    "rule": by.get("rule"),
                    "layer": by.get("layer"),
                    "owner": by.get("owner"),
                    "reason": by.get("reason"),
                }
            )
    return {
        "notes": notes,
        "findings": shown,
        "information": [f for f in in_effect if f not in listed],
        "timeline": timeline,
        "suppressed": suppressed,
        "bundle": row or None,
        "custody": stored.get("custody") or [],
        "collected_at": row.get("started_at"),
    }


def _event_refs(finding: dict) -> list[int]:
    refs = finding.get("evidence")
    refs = refs if isinstance(refs, list) else []
    return [r["event"] for r in refs if isinstance(r, dict) and isinstance(r.get("event"), int)]


def _with_excerpts(finding, events, snapshot, baselines, excerpts, snapshot_type) -> dict:
    """A finding's excerpts. "and N more" counts only what could really be shown, and a
    reference that leads nowhere is said, so nothing reads as more evidence than there is."""
    try:
        found = excerpts(finding, events, snapshot or snapshot_type({}, {}), baselines)
    except Exception:  # noqa: BLE001 - one finding's odd data loses its own excerpts only
        return {**_finding(finding), "excerpts": [], "missing": True}
    real = [e for e in found if e.get("where") or e.get("when")]
    sources = {str(visible(e.source, 80)) for e in events}
    real = [{**e, "from_server": str(e.get("where")) in sources} for e in real]
    refs = finding.get("evidence")
    refs = [r for r in refs if isinstance(r, dict)] if isinstance(refs, list) else []
    lost = sum(
        1
        for r in refs
        if "event" in r and not (isinstance(r["event"], int) and 0 <= r["event"] < len(events))
    )
    beyond = len(refs) - lost - len(real)
    if beyond > 0:
        real.append({"where": "", "when": "", "text": f"… and {beyond} more"})
    return {**_finding(finding), "excerpts": real, "missing": lost > 0 or snapshot is None}


def when(moment: object) -> str:
    """A time as people read it. Anything else is shown as it is."""
    try:
        parsed = datetime.fromisoformat(str(moment))
        return (
            parsed.astimezone(UTC).strftime("%-d %b %Y, %H:%M UTC")
            if parsed.tzinfo
            else str(moment)
        )
    except (ValueError, OverflowError):
        return str(moment)

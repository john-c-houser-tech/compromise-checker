"""What the fleet means, in words for someone who has never read a log. The tool's own
results stay exact in checker.fleet; this says them plainly and says what to do.

The rule that matters: green has to be earned. A server reads "no strong signs" only if
its score is Low and nothing in `_cautions` has anything to say. Anything new the fleet
learns to report belongs there, not in a note beside a reassuring result."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from checker.fleet import UNREADABLE, FleetHost, serious, sort_key
from checker.report import OLDER_CHECKS
from checker.schedule import SERIOUS

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
    ("it can see less than before", f"The check can see less than before.{LOGS_MISSING}", False),
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
    open_now = sorted(p for p, how in exposed.items() if how in ("vulnerable", "can't judge"))
    if open_now:
        cautions.append(_Caution("Open to a known threat", "Update this server."))
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
    if any("threat pack" in line for line in host.changes):
        cautions.append(_Caution("A sign of a known threat was found", "Look into this today."))
    earlier = host.band_before in ("High", "Critical") or host.rescored_from in ("High", "Critical")
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
    exposures = tuple(
        EXPOSURE_WORDS[how].format(pack)
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

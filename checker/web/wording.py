"""What the fleet means, in words for someone who has never read a log. The tool's own
results stay exact in checker.fleet; this says them plainly and says what to do."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from checker.fleet import UNREADABLE, FleetHost, sort_key
from checker.schedule import EXPOSED

# How worrying each state is, for colour and for what the page leads with.
VERDICTS = {
    "Critical": ("critical", "Strong signs of a break-in", "Act on this now."),
    "High": ("high", "Signs of a break-in", "Look into this today."),
    "Elevated": ("elevated", "Some warning signs", "Look into this soon."),
    "Low": ("low", "No strong signs of a break-in", ""),
}
NOT_ANALYSED = {
    "not_analysed": "Checked, but the results haven't been worked out yet.",
    "no_evidence": "This server hasn't been checked yet.",
    "collections_failed": "Every check of this server has failed so far.",
    "purged": "This server's old results were deleted, so nothing is known about it now.",
}
TONE_NAMES = {
    "critical": "Strong signs",
    "high": "Signs of a break-in",
    "unknown": "Can't be vouched for",
    "elevated": "Warning signs",
    "low": "No strong signs",
}
# The tool's reasons for doubt, by how they start, as a reader would want them.
SETTINGS_CHANGED = "Settings have changed since this result, so it may change at the next check."
DOUBTS = (
    ("its last collection was", "The last check didn't finish, so this result may be out of date."),
    ("this collection was", "The last check only saw part of this server."),
    ("a newer collection", "A newer check hasn't been worked out yet."),
    ("collected more than", "This server hasn't been checked recently."),
    ("checks that couldn't run", "Some of the checks couldn't run."),
    (
        "it can see less than before",
        "The check can see less of this server than before. Logs can go missing when someone"
        " covers their tracks.",
    ),
    ("no authentication log events", "The check can't see any record of logins on this server."),
    ("no system journal events", "The check can't see the system's own log on this server."),
    ("the whitelist", SETTINGS_CHANGED),
    ("a whitelist rule", SETTINGS_CHANGED),
    ("its whitelist", "Its list of accepted activity can't be read, so that result may change."),
    ("the threat packs", SETTINGS_CHANGED),
    ("the host's starting", SETTINGS_CHANGED),
    ("part of its analysis", "Part of this result couldn't be worked out."),
)
EXPOSURE_WORDS = {
    "fixed": "was open to this threat while it was active, and is fixed now",
    "can't judge": "may be open to this threat: the check can't tell",
    "vulnerable": "is open to this threat now",
}


_BAND_MOVE = re.compile(r"(Low|Elevated|High|Critical) to (Low|Elevated|High|Critical)\b")


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


def plain_doubt(doubt: str) -> str:
    for start, words in DOUBTS:
        if doubt.startswith(start):
            return words
    return doubt


def ago(moment: str | None, now: datetime) -> str:
    if not moment:
        return ""
    try:
        seconds = (now - datetime.fromisoformat(moment)).total_seconds()
    except (TypeError, ValueError):
        return ""
    if seconds < 3600:
        return "Checked within the last hour"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"Checked {hours} hour{'s' if hours != 1 else ''} ago"
    days = int(seconds // 86400)
    return f"Checked {days} day{'s' if days != 1 else ''} ago"


def _change(line: str) -> str | None:
    """A line of alerts() ("host: what") for the list of what's new, or None if it is
    said elsewhere on the row: the move between bands, or an exposure to a threat."""
    what = line.partition(": ")[2] or line
    if _BAND_MOVE.match(what) or what.startswith("exposed to threat pack "):
        return None
    for start in ("new critical: ", "new high: "):
        if what.startswith(start):
            return what[len(start) :]
    return what


def row(host: FleetHost, now: datetime | None = None) -> Row:
    now = now or datetime.now(UTC)
    notes = list(dict.fromkeys(plain_doubt(d) for d in host.doubts))
    if host.state == "unreadable":
        verdict = "This result can't be read"
        tone, action = "critical", "Find out why before trusting anything about this server."
        notes.insert(0, UNREADABLE.get(host.unreadable_why or "internal", "").capitalize())
        if host.last_readable_band:
            said = VERDICTS.get(host.last_readable_band, (None, "no score", None))[1].lower()
            notes.append(f"The last result that could be read said: {said}.")
    elif host.state != "analysed":
        tone, verdict, action = "unknown", "Nothing to go on yet", NOT_ANALYSED.get(host.state, "")
    else:
        tone, verdict, action = VERDICTS.get(host.band, ("unknown", "No score", ""))
        if notes and tone in ("low", "elevated"):
            verdict = (
                "No strong signs, but don't rely on this yet"
                if tone == "low"
                else "Some warning signs, and this may not be the whole picture"
            )
            tone, action = "unknown", "Run a fresh check."
        elif notes:
            action = f"{action} This result may have changed since."
    if host.removed:
        notes.append("No longer on your list of servers, so it isn't being checked.")
    if (
        host.last_failed
        and host.state != "collections_failed"
        and not any("didn't finish" in n for n in notes)
    ):
        notes.append("The last check didn't finish.")
    if host.not_seen:
        notes.append(
            "Some earlier warnings weren't seen this time, which doesn't mean they've gone."
        )
    if host.suppressed:
        notes.append("Some earlier warnings are now hidden by your list of accepted activity.")
    changes = [c for c in map(_change, host.changes) if c]
    if host.band_before and host.band_before != host.band and host.state == "analysed":
        before = VERDICTS.get(host.band_before, (None, str(host.band_before), None))[1]
        notes.append(f"At the check before: {before.lower()}.")
    if host.resolved:
        notes.append(
            f"{host.resolved} serious warning{'s' if host.resolved != 1 else ''} gone"
            " since the check before."
        )
    exposures = tuple(
        f"This server {EXPOSURE_WORDS.get(how, how)}: {pack}."
        for pack, how in sorted(host.exposed.items())
        if how in EXPOSED
    )
    return Row(
        host,
        tone,
        verdict,
        action,
        tuple(notes),
        tuple(changes),
        exposures,
        ago(host.collected_at, now),
    )


def headline(rows: list[Row]) -> tuple[str, str]:
    """The answer the page opens with, from the most worrying thing on it, and its tone."""
    total = len(rows)
    if not total:
        return "No servers yet.", "unknown"

    def count(*tones: str) -> int:
        return sum(1 for r in rows if r.tone in tones)

    def of(n: int) -> str:
        if total == 1:
            return "Your server"
        return f"{n} of your {total} servers"

    def verb(n: int, one: str, many: str) -> str:
        return one if n == 1 or total == 1 else many

    urgent = count("critical", "high")
    if urgent:
        return f"{of(urgent)} {verb(urgent, 'needs', 'need')} attention now.", "critical"
    unknown = count("unknown")
    if unknown:
        return f"{of(unknown)} can't be vouched for right now.", "unknown"
    elevated = count("elevated")
    if elevated:
        return f"{of(elevated)} {verb(elevated, 'has', 'have')} some warning signs.", "elevated"
    where = "your server" if total == 1 else f"your {total} servers"
    return f"No strong signs of a break-in on {where}.", "low"


def rows_for(hosts: list[FleetHost], now: datetime | None = None) -> list[Row]:
    return [row(h, now) for h in sorted(hosts, key=sort_key)]

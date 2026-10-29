"""Checks (DESIGN.md §8): small rules over a bundle's events and snapshot,
and its changes since the host's baseline, each producing findings.

A finding says what was seen, how much it matters (a band, and the
likelihood ratio scoring gives it, checker/scoring.py), whether it is a sign of compromise,
of poor hygiene or of exposure (principle 9), what it involves, and which
events, snapshot items and changes show it."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from checker.events import Event
from checker.snapshot import Snapshot

# 2: the critical band, variants; 3: more variants; 4: exe entities and
# entities_complete; 5: sudo.rules name the account or group; 6: account
# and key variants; 7: network checks (8.8); 8: anti-forensics (8.10); 9:
# software changes (8.11); 10: outgoing mail (8.9); 11: web applications (8.12);
# 12: containers (8.13).
CHECKS_VERSION = 12

COMPROMISE = "compromise indicator"
HYGIENE = "hygiene"
EXPOSURE = "exposure"
CATEGORIES = (COMPROMISE, EXPOSURE, HYGIENE)
# critical: the strongest signs (DESIGN.md §11.1's critical examples);
# high: DESIGN.md §8's ★ checks. The likelihood ratio behind each band is
# in checker/scoring.py.
BANDS = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    check: str  # the check's id, e.g. "account.uid0"
    title: str
    category: str
    band: str
    summary: str  # one line: what, who, where
    entities: list[str] = field(default_factory=list)  # "account:eve", "address:203.0.113.9"
    # What shows it: {"event": index}, {"item": [section, key]},
    # {"change": [against, section, key, how]} or {"live": ["processes", pid]}.
    evidence: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    new: bool = False  # changed since the previous bundle, not only since the baseline
    uncertain: str | None = None  # why it may be wrong (a section not fully collected)
    # Which of a check's kinds of finding this is, where they differ in
    # weight (scoring's overrides, whitelists).
    variant: str | None = None
    # False when `entities` lists only some of what the finding is about (a
    # group of many files): a whitelist rule naming an entity can't vouch
    # for the ones not listed, so it doesn't match.
    entities_complete: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Context:
    """What a check reads."""

    host: str
    bundle_id: str
    events: list[Event]
    snapshot: Snapshot
    baseline_id: str | None = None
    since_baseline: dict[str, dict[str, Any]] | None = None  # None: nothing to compare with
    since_previous: dict[str, dict[str, Any]] | None = None
    # Earlier bundles' events, oldest first, loaded only if a check asks.
    earlier_events: Callable[[], list[list[Event]]] = lambda: []
    scanner: str | None = None  # the account the tool logs in as
    # When the previous bundle was collected (controller clock): an event
    # before it was in that bundle's analysis already.
    previous_time: str | None = None
    # Why change-based checks can't run, when they can't.
    no_baseline: str = "no baseline yet"
    # The previous bundle's snapshot, for what only its live part shows (a
    # log that shrank since then).
    previous_snapshot: Snapshot | None = None
    # When the baseline was collected (controller clock), and its snapshot:
    # what logs show after it is judged against what they showed before
    # (mail volume), and its live part against this one's (queue size).
    baseline_time: str | None = None
    baseline_snapshot: Snapshot | None = None

    def of(self, *types: str) -> Iterator[tuple[int, Event]]:
        """(index, event) for events of these types (or type prefixes ending
        in "."), the tool's own session left out."""
        for index, event in enumerate(self.events):
            if event.own_session:
                continue
            if any(
                event.type == t or (t.endswith(".") and event.type.startswith(t)) for t in types
            ):
                yield index, event

    def items(self, section: str) -> dict[str, dict[str, Any]]:
        found = self.snapshot.sections.get(section)
        return found.items if found else {}

    def changes(self, section: str) -> dict[str, Any] | None:
        """The section's changes since the baseline (added, removed,
        changed, comparable, notes); None when there is no baseline to
        compare with yet, an empty change when nothing changed."""
        if self.since_baseline is None:
            return None
        return self.since_baseline.get(
            section, {"added": {}, "removed": {}, "changed": {}, "comparable": True, "notes": []}
        )

    def new_since_previous(self, section: str, key: str) -> bool:
        if self.since_previous is None:
            return True
        diff = self.since_previous.get(section) or {}
        if not diff.get("comparable", True) and not any(
            diff.get(kind) for kind in ("added", "removed", "changed")
        ):
            return True  # the previous bundle didn't collect it: can't say it isn't new
        return any(key in diff.get(kind, {}) for kind in ("added", "removed", "changed"))

    def change_ref(self, section: str, key: str, how: str) -> dict[str, Any]:
        return {"change": [self.baseline_id, section, key, how]}

    def uncertain(self, section: str) -> str | None:
        """Why a change-based finding in a section may be wrong."""
        diff = self.changes(section)
        if diff and not diff["comparable"]:
            return "; ".join(diff["notes"])
        current = self.snapshot.sections.get(section)
        if current is not None and not current.complete:
            return "not fully collected: " + "; ".join(current.gaps[:3])
        return None


def span(events: list[Event]) -> tuple[str | None, str | None]:
    times = sorted(e.corrected for e in events if e.corrected)
    return (times[0], times[-1]) if times else (None, None)


@dataclass
class Check:
    id: str
    title: str
    needs_baseline: bool
    run: Callable[[Context], list[Finding]]
    # The kinds of finding it reports, where they weigh differently or a
    # whitelist rule may want one only (Finding.variant).
    variants: tuple[str, ...] = ()


REGISTRY: list[Check] = []


def check(id: str, title: str, *, needs_baseline: bool = False, variants: tuple[str, ...] = ()):
    """Register a check: a function from a Context to findings."""

    def register(run: Callable[[Context], list[Finding]]):
        REGISTRY.append(Check(id, title, needs_baseline, run, variants))
        return run

    return register


def load_checks() -> dict[str, Check]:
    """Every check, by id (importing the modules registers them)."""
    from checker.checks import (  # noqa: F401 - they register
        accounts,
        antiforensics,
        containers,
        files,
        integrity,
        kernel,
        mail,
        network,
        persistence,
        processes,
        reboots,
        software,
        web,
    )

    return {c.id: c for c in REGISTRY}


def run_checks(context: Context) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Every check's findings, most serious first, and a line per check:
    whether it ran, was skipped (no baseline yet) or failed."""
    load_checks()
    findings: list[Finding] = []
    ran: list[dict[str, Any]] = []
    # By id: the registry's order is whatever order the modules happened to
    # be imported in, and the list of what ran must not depend on that.
    for item in sorted(REGISTRY, key=lambda c: c.id):
        if item.needs_baseline and context.since_baseline is None:
            ran.append({"check": item.id, "status": context.no_baseline})
            continue
        try:
            found = item.run(context)
        except Exception as exc:  # one broken check must not hide the others
            ran.append({"check": item.id, "status": f"failed: {type(exc).__name__}: {exc}"})
            continue
        ran.append({"check": item.id, "status": "ran", "findings": len(found)})
        findings += found
    previous = parse_time(context.previous_time)
    for finding in findings:
        # A finding from the logs alone is new when its latest event came
        # after the previous bundle was collected.
        if any("change" in ref for ref in finding.evidence):
            continue
        if any("event" in ref for ref in finding.evidence):
            last = parse_time(finding.last_seen)
            finding.new = previous is None or last is None or last > previous
    order = {band: i for i, band in enumerate(BANDS)}
    findings.sort(key=lambda f: (order[f.band], CATEGORIES.index(f.category), f.check, f.summary))
    return findings, ran


def parse_time(text: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(text) if text else None
    except ValueError:
        return None

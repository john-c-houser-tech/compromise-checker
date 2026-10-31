"""The fleet at a glance (DESIGN.md §13): each host's latest analysis, what
changed since the one before, and how far it can be relied on. Read from
what is stored: nothing here collects, analyses or writes, so looking can't
change what the report would say. The web interface reads through this."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from checker.assess import load_assessment
from checker.baseline import usable_bundles
from checker.report import out_of_date
from checker.schedule import BANDS, SERIOUS, _exposed, _identity_of, alerts, remembered

# A result older than this is said to be old: a weekly check, and a day's grace.
STALE_AFTER = timedelta(days=8)

# Most worrying first. An analysis that can't be read comes before everything:
# the tool's own store may have been tampered with. A host nobody can vouch for
# comes after High and Critical, which are known problems, and before Elevated
# and Low, which are known to be less so: it must not sink to the bottom.
_UNREADABLE, _UNKNOWN = -1, 2
_ORDER = {"Critical": 0, "High": 1, "Elevated": 3, "Low": 4}


@dataclass(frozen=True)
class FleetHost:
    host: str
    group: str | None = None
    # analysed: there is an analysis to show (see `doubts`, `out_of_date`);
    # not_analysed: evidence is stored, with no analysis of it;
    # no_evidence: nothing has been collected;
    # collections_failed: collections were tried, and none was usable;
    # purged: all its evidence was purged, so nothing is known now;
    # unreadable: its stored analysis can't be read or doesn't match its hash.
    state: str = "no_evidence"
    band: str | None = None
    probability: float | None = None
    counts: dict[str, int] = field(default_factory=dict)
    # Each threat pack the host was exposed to, with how, and the packs whose
    # exposure this analysis couldn't judge (one known before stays in `exposed`).
    exposed: dict[str, str] = field(default_factory=dict)
    unjudged: tuple[str, ...] = ()
    gaps: int = 0
    collected_at: str | None = None
    analysed_at: str | None = None
    collection_status: str | None = None
    # The last collection, when it wasn't usable: its status and when.
    last_failed: tuple[str, str] | None = None
    # Why a reassuring result may be wrong: nothing recent stands behind it.
    doubts: tuple[str, ...] = ()
    # Why the analysis shown may not be what the report would say now.
    out_of_date: tuple[str, ...] = ()
    # With an unreadable analysis: what the last readable one said, never
    # shown as current.
    last_readable_band: str | None = None
    # Since the analysis before; `first` when there was none to compare with.
    first: bool = True
    before_unreadable: bool = False
    band_before: str | None = None
    # The same collection scored with another band (a whitelist or prior changed).
    rescored_from: str | None = None
    changes: tuple[str, ...] = ()
    # High and critical findings in effect before that aren't now: no longer
    # found in a whole collection, now suppressed by a whitelist, or not found
    # in a collection that was only partial, which says nothing either way.
    resolved: int = 0
    suppressed: int = 0
    not_seen: int = 0


@dataclass
class _Found:
    """The newest analysis readable, the one before it, and what got in the way."""

    row: Any = None
    after: dict | None = None
    before: dict | None = None
    newest_unreadable: bool = False
    before_unreadable: bool = False


def _analyses(store, usable: list, identity) -> _Found:
    found = _Found()
    for row in reversed(usable):
        try:
            assessment = load_assessment(store, row["id"], identity)
        except Exception:  # noqa: BLE001 - tampered or the wrong key: said, and never hidden
            if found.after is None:
                found.newest_unreadable = True
            else:
                found.before_unreadable = True
            if found.before_unreadable:
                return found
            continue
        if assessment is None:
            continue
        if found.after is None:
            found.row, found.after = row, assessment
            if found.newest_unreadable:
                return found  # only to say what it said
        else:
            found.before = assessment
            return found
    return found


def _earlier_of_same_bundle(store, bundle_id: str, identity) -> dict | None:
    """The analysis of this collection before its latest, if there was one."""
    if len(store.assessments(bundle_id)) < 2:
        return None
    try:
        return load_assessment(store, bundle_id, identity, which=-2)
    except Exception:  # noqa: BLE001 - only history: the latest is what is shown
        return None


def _gone(before: dict | None, after: dict, complete: bool) -> tuple[int, int, int]:
    """(resolved, suppressed, not seen) of what was serious before."""
    if not before:
        return 0, 0, 0
    now = {_identity_of(f) for f in after.get("findings") or [] if not f.get("suppressed_by")}
    hidden = {_identity_of(f) for f in after.get("findings") or [] if f.get("suppressed_by")}
    resolved = suppressed = not_seen = 0
    for key, band in (before.get("findings") or {}).items():
        if band not in SERIOUS or key in now:
            continue
        if key in hidden:
            suppressed += 1
        elif complete:
            resolved += 1
        else:
            not_seen += 1
    return resolved, suppressed, not_seen


def _old(started_at: str, now: datetime) -> bool:
    try:
        return now - datetime.fromisoformat(started_at) > STALE_AFTER
    except (TypeError, ValueError):
        return True


def _purged(store) -> set[str]:
    return {host for row in store.purges() for host in json.loads(row["baselines"])}


def fleet_host(
    store,
    host: str,
    identity,
    group: str | None = None,
    prior_for: Callable[[str], tuple[float, str]] | None = None,
    whitelist_for: Callable[[str], Any] | None = None,
    packs_for: Callable[[str], tuple[list, list[str]]] | None = None,
    now: datetime | None = None,
) -> FleetHost:
    now = now or datetime.now(UTC)
    rows = store.bundles(host)
    usable = usable_bundles(store, host)
    last_failed = None
    if rows and (not usable or rows[-1]["id"] != usable[-1]["id"]):
        last_failed = (rows[-1]["status"], rows[-1]["started_at"])
    found = _analyses(store, usable, identity)
    if found.newest_unreadable:
        return FleetHost(
            host,
            group,
            "unreadable",
            last_failed=last_failed,
            last_readable_band=((found.after or {}).get("score") or {}).get("band"),
        )
    if found.after is None:
        if usable:
            state = "not_analysed"
        elif rows:
            state = "collections_failed"
        else:
            state = "purged" if host in _purged(store) else "no_evidence"
        return FleetHost(
            host,
            group,
            state,
            collected_at=usable[-1]["started_at"] if usable else None,
            last_failed=last_failed,
        )
    row, after = found.row, found.after
    reasons: list[str] = []
    whitelist = None
    check_whitelist = whitelist_for is not None
    if whitelist_for is not None:
        try:
            whitelist = whitelist_for(host)
        except Exception:  # noqa: BLE001 - one broken file mustn't hide the others' results
            check_whitelist = False
            reasons.append("its whitelist can't be read")
    packs, problems = packs_for(host) if packs_for else (None, None)
    analyse, rescore = out_of_date(
        after,
        prior_for(host) if prior_for else None,
        whitelist,
        packs,
        problems,
        check_packs=packs_for is not None,
        check_whitelist=check_whitelist,
    )
    reasons += [*analyse, *rescore]
    doubts = []
    if row["id"] != usable[-1]["id"]:
        reasons.insert(0, "a newer collection hasn't been analysed")
        doubts.append("a newer collection hasn't been analysed")
    if last_failed:
        doubts.append(f"its last collection was {last_failed[0]}")
    if row["status"] != "complete":
        doubts.append(f"this collection was {row['status']}")
    if _old(row["started_at"], now):
        doubts.append(f"collected more than {STALE_AFTER.days} days ago")

    earlier = _earlier_of_same_bundle(store, row["id"], identity)
    previous = found.before or earlier
    before = remembered(previous, remembered(earlier) if found.before and earlier else None)
    memory = remembered(after, before)
    score = after.get("score") or {}
    probability = score.get("probability")
    resolved, suppressed, not_seen = _gone(before, after, row["status"] == "complete")
    rescored = (earlier.get("score") or {}).get("band") if earlier else None
    return FleetHost(
        host,
        group,
        "analysed",
        band=score.get("band"),
        probability=probability if isinstance(probability, (int, float)) else None,
        counts=dict(after.get("counts") or {}),
        exposed=dict(memory["exposed"]) if memory else {},
        unjudged=tuple(sorted(_exposed(after)[1])),
        gaps=len((after.get("coverage") or {}).get("gaps") or []),
        collected_at=row["started_at"],
        analysed_at=after.get("analysed_at"),
        collection_status=row["status"],
        last_failed=last_failed,
        doubts=tuple(doubts),
        out_of_date=tuple(reasons),
        first=before is None and not found.before_unreadable,
        before_unreadable=found.before_unreadable,
        band_before=before["band"] if before else None,
        rescored_from=rescored if rescored != score.get("band") else None,
        changes=tuple(alerts(host, before, after)) if before else (),
        resolved=resolved,
        suppressed=suppressed,
        not_seen=not_seen,
    )


def sort_key(item: FleetHost) -> tuple:
    if item.state == "unreadable":
        rank = _UNREADABLE
    elif item.band not in BANDS:
        rank = _UNKNOWN
    elif item.doubts and _ORDER[item.band] > _UNKNOWN:
        rank = _UNKNOWN  # reassuring, with nothing recent behind it
    else:
        rank = _ORDER[item.band]
    return (rank, -(item.probability or 0), item.host)


def fleet(
    store,
    identity,
    groups: dict[str, str | None],
    prior_for=None,
    whitelist_for=None,
    packs_for=None,
    group: str | None = None,
    now: datetime | None = None,
) -> list[FleetHost]:
    """Every host in the inventory or the store, most worrying first.
    `groups` is the inventory's name → group. A host no longer in the
    inventory has no group, so it shows under any filter: a removed host's
    bad result shouldn't be filtered out of sight."""
    names = set(groups) | set(store.hosts())

    def one(name: str) -> FleetHost:
        try:
            return fleet_host(
                store,
                name,
                identity,
                groups.get(name),
                prior_for,
                whitelist_for,
                packs_for,
                now,
            )
        except Exception:  # noqa: BLE001 - one host's odd data mustn't blank the fleet
            return FleetHost(name, groups.get(name), "unreadable")

    return sorted(
        (one(n) for n in names if group is None or n not in groups or groups[n] == group),
        key=sort_key,
    )

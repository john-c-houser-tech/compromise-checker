"""The fleet at a glance (DESIGN.md §13): each host's latest analysis, what
changed since the one before, and whether it is still current. Read from
what is stored: nothing here collects, analyses or writes, so looking can't
change what the report would say. The web interface reads through this."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from checker.assess import load_assessment
from checker.baseline import usable_bundles
from checker.report import out_of_date
from checker.schedule import BANDS, SERIOUS, _exposed, alerts, remembered

# Most worrying first. A host nobody can vouch for comes after High and
# Critical, which are known problems, and before Elevated and Low, which are
# known to be less so: it must not sink to the bottom of the page.
_ORDER = {"Critical": 0, "High": 1, None: 2, "Elevated": 3, "Low": 4}


@dataclass(frozen=True)
class FleetHost:
    host: str
    group: str | None = None
    # analysed: there is an analysis to show (it may be out of date);
    # not_analysed: evidence is stored, with no analysis of it;
    # no_evidence: nothing usable has been collected;
    # unreadable: the stored analysis can't be read or doesn't match its hash.
    state: str = "no_evidence"
    band: str | None = None
    probability: float | None = None
    counts: dict[str, int] = field(default_factory=dict)
    # Each threat pack the host was exposed to, with how.
    exposed: dict[str, str] = field(default_factory=dict)
    gaps: int = 0
    collected_at: str | None = None
    analysed_at: str | None = None
    # The last collection, when it wasn't usable: its status and when.
    last_failed: tuple[str, str] | None = None
    # Why the analysis shown may not be what the report would say now.
    out_of_date: tuple[str, ...] = ()
    # Since the analysis before; `first` when there was none to compare with.
    first: bool = True
    band_before: str | None = None
    changes: tuple[str, ...] = ()
    gone: int = 0


def _analyses(store, host: str, identity) -> tuple[list[tuple[Any, dict]], bool]:
    """The newest two usable bundles' analyses that exist, newest first, and
    whether one that exists couldn't be read."""
    found: list[tuple[Any, dict]] = []
    for row in reversed(usable_bundles(store, host)):
        try:
            assessment = load_assessment(store, row["id"], identity)
        except Exception:  # noqa: BLE001 - tampered or the wrong key: said, and not hidden behind an older one
            return found, True
        if assessment is not None:
            found.append((row, assessment))
            if len(found) == 2:
                break
    return found, False


def _gone(before: dict | None, after: dict | None) -> int:
    """High and critical findings in effect before that aren't now."""
    if not before or not after:
        return 0
    now = after.get("findings") or {}
    earlier = (before.get("findings") or {}).items()
    return sum(1 for key, band in earlier if band in SERIOUS and key not in now)


def fleet_host(
    store,
    host: str,
    identity,
    group: str | None = None,
    prior_for: Callable[[str], tuple[float, str]] | None = None,
    whitelist_for: Callable[[str], Any] | None = None,
    packs_for: Callable[[str], tuple[list, list[str]]] | None = None,
) -> FleetHost:
    rows = store.bundles(host)
    latest = rows[-1] if rows else None
    last_failed = None
    usable = usable_bundles(store, host)
    if latest is not None and (not usable or latest["id"] != usable[-1]["id"]):
        last_failed = (latest["status"], latest["started_at"])
    found, unreadable = _analyses(store, host, identity)
    if unreadable and not found:
        return FleetHost(host, group, "unreadable", last_failed=last_failed)
    if not found:
        return FleetHost(
            host,
            group,
            "not_analysed" if usable else "no_evidence",
            collected_at=usable[-1]["started_at"] if usable else None,
            last_failed=last_failed,
        )
    row, after = found[0]
    packs, problems = packs_for(host) if packs_for else (None, None)
    analyse, reassess = out_of_date(
        after,
        prior_for(host) if prior_for else None,
        whitelist_for(host) if whitelist_for else None,
        packs,
        problems,
        check_packs=packs_for is not None,
        check_whitelist=whitelist_for is not None,
    )
    reasons = [*analyse, *reassess]
    if row["id"] != usable[-1]["id"]:
        reasons.insert(0, "a newer collection hasn't been analysed")
    if unreadable:
        reasons.insert(0, "a newer analysis can't be read")
    before = remembered(found[1][1]) if len(found) > 1 and not unreadable else None
    now = remembered(after)
    score = after.get("score") or {}
    probability = score.get("probability")
    return FleetHost(
        host,
        group,
        "analysed",
        band=score.get("band"),
        probability=probability if isinstance(probability, (int, float)) else None,
        counts=dict(after.get("counts") or {}),
        exposed=_exposed(after)[0],
        gaps=len((after.get("coverage") or {}).get("gaps") or []),
        collected_at=row["started_at"],
        analysed_at=after.get("analysed_at"),
        last_failed=last_failed,
        out_of_date=tuple(reasons),
        first=before is None,
        band_before=before["band"] if before else None,
        changes=tuple(alerts(host, before, after)) if before else (),
        gone=_gone(before, now),
    )


def sort_key(item: FleetHost) -> tuple:
    known = item.band if item.band in BANDS else None
    return (_ORDER[known], -(item.probability or 0), item.host)


def fleet(
    store,
    identity,
    groups: dict[str, str | None],
    prior_for=None,
    whitelist_for=None,
    packs_for=None,
    group: str | None = None,
) -> list[FleetHost]:
    """Every host in the inventory or the store, most worrying first.
    `groups` is the inventory's name → group."""
    names = set(groups) | set(store.hosts())
    return sorted(
        (
            fleet_host(store, name, identity, groups.get(name), prior_for, whitelist_for, packs_for)
            for name in names
            if group is None or groups.get(name) == group
        ),
        key=sort_key,
    )

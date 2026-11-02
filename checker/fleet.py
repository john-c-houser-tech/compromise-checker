"""The fleet at a glance (DESIGN.md §13): each host's latest analysis, what
changed since the one before, and how far it can be relied on. Read from
what is stored: nothing here collects, analyses or writes, so looking can't
change what the report would say. The web interface reads through this."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyrage

from checker.assess import load_assessment
from checker.baseline import usable_bundles
from checker.database import DATABASE_ERRORS
from checker.evidence import EvidenceError, store_unreadable
from checker.report import OLDER_CHECKS, out_of_date, visible
from checker.schedule import BANDS, SERIOUS, _exposed, _identity_of, alerts, remembered

# A collection older than this is said to be old unless the settings say
# otherwise (stale_after_days): a daily check, and time for a bad weekend.
STALE_AFTER = timedelta(days=3)
# How far back to look for what an unjudged exposure last was.
_EXPOSURE_LOOKBACK = 30

# Most worrying first. An analysis that can't be read comes before everything:
# the tool's own store may have been tampered with. A host nobody can vouch for
# comes after High and Critical, which are known problems, and before Elevated
# and Low, which are known to be less so: it must not sink to the bottom.
_UNREADABLE, _UNKNOWN = -1, 2
_ORDER = {"Critical": 0, "High": 1, "Elevated": 3, "Low": 4}

# With these it can't see logins or the system's own log at all, whatever an
# earlier analysis saw: wiped logs look like this, and from the second day on
# there is nothing "new" about them. So they are always a doubt.
_BLIND = ("no authentication log events", "no system journal events")

_NOT_HIDING = ("pack ", "threat pack ", "login hours not judged")

# Why an analysis can't be read, in words for whoever is looking.
UNREADABLE = {
    "mismatch": "its stored analysis doesn't match its recorded hash: it may have been"
    " tampered with",
    "missing": "its stored analysis file is missing",
    "key": "its stored analysis can't be decrypted with this evidence key",
    "damaged": "its stored analysis is damaged",
    "internal": "its stored data couldn't be worked out: this may be a bug in the tool",
}


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
    # With an unreadable analysis: why, and what the last readable one said,
    # never shown as current.
    unreadable_why: str | None = None
    last_readable_band: str | None = None
    # No longer in the inventory, so no longer collected.
    removed: bool = False
    # The separate hygiene and exposure rating (DESIGN.md §2 principle 9).
    hygiene: str | None = None
    # In effect now: findings a threat pack raised or weighs (signs of that threat), and
    # programs still running code from before a threat's fix.
    threat_signs: int = 0
    stale_code: int = 0
    # What its analysis recorded about each threat pack, as recorded (pack id: status, share,
    # judged, exposed_until), and which pack versions it applied.
    pack_records: dict[str, dict] = field(default_factory=dict)
    # With the package history unread, a first install can't be told from a fix, so what's
    # recorded about a threat is an upper limit.
    package_history_incomplete: bool = False
    packs_applied: dict[str, int] = field(default_factory=dict)
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
    before_row: Any = None
    newest_unreadable: str | None = None
    before_unreadable: bool = False


def _load(store, bundle_id: str, identity, which: int = -1) -> tuple[dict | None, str | None]:
    """An analysis, or why it can't be read. A store that can't answer isn't
    one host's problem: that goes up to fleet()."""
    try:
        return load_assessment(store, bundle_id, identity, which), None
    except DATABASE_ERRORS:
        raise
    except EvidenceError:
        return None, "mismatch"
    except OSError:
        return None, "missing"
    except pyrage.DecryptError:
        return None, "key"
    except Exception:  # noqa: BLE001 - gzip, JSON: damaged, whatever the detail
        return None, "damaged"


def _analyses(store, usable: list, identity) -> _Found:
    found = _Found()
    for row in reversed(usable):
        assessment, why = _load(store, row["id"], identity)
        if why:
            if found.after is not None:
                found.before_unreadable = True
                return found
            found.newest_unreadable = found.newest_unreadable or why
            continue
        if assessment is None:
            continue
        if found.after is None:
            found.row, found.after = row, assessment
            if found.newest_unreadable:
                return found  # only to say what it said
        else:
            found.before, found.before_row = assessment, row
            return found
    return found


def _known_exposure(store, assessment: dict, older: list, identity) -> dict[str, str]:
    """The packs a host was exposed to: this analysis's, and for one it couldn't
    judge, the latest older analysis that could. So disturbing a package listing,
    however many times, doesn't clear a known exposure."""
    exposed, unjudged = _exposed(assessment)
    for row in list(reversed(older))[:_EXPOSURE_LOOKBACK]:
        if not unjudged:
            break
        earlier, _ = _load(store, row["id"], identity)
        if earlier is None:
            continue
        then, unjudged_then = _exposed(earlier)
        for pack in unjudged - unjudged_then:
            if pack in then:
                exposed[pack] = then[pack]
        unjudged &= unjudged_then
    return exposed


def _same_finding(one: list, other: list) -> bool:
    """Two identities (schedule._identity_of) of one finding: the same check and
    variant, and the same entities or some in common. A group listed in part
    (its identity has a fourth part, the summary) keeps only some of its members,
    so a new member can push a listed one out: it is the same finding still."""
    if one[:2] != other[:2]:
        return False
    if len(one) > 3 or len(other) > 3 or one[2] == other[2]:
        return True
    return (
        isinstance(one[2], list)
        and isinstance(other[2], list)
        and bool(set(one[2]) & set(other[2]))
    )


def _gone(before: dict | None, after: dict, comparable: bool) -> tuple[int, int, int]:
    """(resolved, suppressed, not seen) of what was serious before. Resolved only
    if the two analyses can be compared: otherwise a finding's absence says
    nothing about the host."""
    if not before:
        return 0, 0, 0
    findings = after.get("findings") or []
    now = [json.loads(_identity_of(f)) for f in findings if not f.get("suppressed_by")]
    hidden = [json.loads(_identity_of(f)) for f in findings if f.get("suppressed_by")]
    resolved = suppressed = not_seen = 0
    for key, band in (before.get("findings") or {}).items():
        was = json.loads(key)
        if band not in SERIOUS or any(_same_finding(was, n) for n in now):
            continue
        if was[0] == "pack.exposure":
            continue  # being open to a threat was never a sign of a break-in: updating ends it
        if any(_same_finding(was, h) for h in hidden):
            suppressed += 1
        elif comparable:
            resolved += 1
        else:
            not_seen += 1
    return resolved, suppressed, not_seen


def _old(started_at: str, now: datetime, stale_after: timedelta) -> bool:
    try:
        age = now - datetime.fromisoformat(started_at)
        # A date in the future vouches for nothing either.
        return age > stale_after or age < -timedelta(days=1)
    except (TypeError, ValueError):
        return True


def _purged(store) -> set[str]:
    return {host for row in store.purges() for host in json.loads(row["baselines"])}


def _gaps(assessment: dict | None) -> list[str]:
    coverage = (assessment or {}).get("coverage")
    gaps = coverage.get("gaps") if isinstance(coverage, dict) else None
    return [str(g) for g in gaps] if isinstance(gaps, list) else []


def _reduces_coverage(gap: str) -> bool:
    """A gap in what the tool set out to read, as opposed to a note about what a host
    simply doesn't have. A long log cut short is routine on a busy server, so it isn't one."""
    return gap.startswith(("not collected:", "error in ")) or " incomplete: " in gap


def _gap_kind(gap: str) -> str:
    """A gap without its numbers: a clock off by another second isn't a new gap."""
    return re.sub(r"[-+]?\d+", "#", gap)


def _in_effect(assessment: dict) -> list[dict]:
    findings = assessment.get("findings")
    if not isinstance(findings, list):
        return []
    return [f for f in findings if isinstance(f, dict) and not f.get("suppressed_by")]


def _exposed_safely(assessment: dict) -> tuple[dict[str, str], set[str]]:
    try:
        return _exposed(assessment)
    except Exception:  # noqa: BLE001 - odd stored data: the raw records still say what they say
        return {}, set()


def _pack_records(assessment: dict) -> dict[str, dict]:
    records = assessment.get("exposures")
    records = records if isinstance(records, list) else []
    return {str(r.get("pack")): r for r in records if isinstance(r, dict)}


def _packs_applied(assessment: dict) -> dict[str, int]:
    applied = assessment.get("packs")
    applied = applied if isinstance(applied, list) else []
    return {str(p.get("id")): p.get("version") for p in applied if isinstance(p, dict)}


def _band_of(assessment: dict | None) -> str | None:
    band = ((assessment or {}).get("score") or {}).get("band")
    return band if isinstance(band, str) else None


def _probability(value: Any) -> float | None:
    """A stored probability, only if it is one: anything else mustn't read as a score."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if 0 <= value <= 1 else None
    except OverflowError:
        return None


def _headline(host: str, group, row, after: dict, last_failed, removed: bool) -> FleetHost:
    """What an analysis says outright, whatever can be worked out beyond it."""
    score = after.get("score") or {}
    return FleetHost(
        host,
        group,
        "analysed",
        band=_band_of(after),
        probability=_probability(score.get("probability")),
        counts={
            str(k): n
            for k, n in dict(after.get("counts") or {}).items()
            if isinstance(n, int) and not isinstance(n, bool)
        },
        gaps=len(_gaps(after)),
        hygiene=(score.get("hygiene_and_exposure") or {}).get("band"),
        pack_records=_pack_records(after),
        package_history_incomplete=any(
            g.startswith("package_history incomplete") for g in _gaps(after)
        ),
        packs_applied=_packs_applied(after),
        # So far as this analysis says: _with_details adds what earlier ones knew.
        exposed=_exposed_safely(after)[0],
        unjudged=tuple(sorted(_exposed_safely(after)[1])),
        threat_signs=sum(
            1
            for f in _in_effect(after)
            if f.get("check") == "pack.detection" or f.get("raised_by_pack")
        ),
        stale_code=sum(
            1
            for f in _in_effect(after)
            if f.get("check") == "pack.exposure" and f.get("variant") == "stale_code"
        ),
        collected_at=row["started_at"],
        analysed_at=after.get("analysed_at"),
        collection_status=row["status"],
        last_failed=last_failed,
        removed=removed,
    )


def fleet_host(
    store,
    host: str,
    identity,
    group: str | None = None,
    prior_for: Callable[[str], tuple[float, str]] | None = None,
    whitelist_for: Callable[[str], Any] | None = None,
    packs_for: Callable[[str], tuple[list, list[str]]] | None = None,
    now: datetime | None = None,
    stale_after: timedelta = STALE_AFTER,
    removed: bool = False,
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
            unreadable_why=found.newest_unreadable,
            last_readable_band=_band_of(found.after),
            removed=removed,
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
            removed=removed,
        )
    headline = _headline(host, group, found.row, found.after, last_failed, removed)
    try:
        return _with_details(
            store,
            headline,
            found,
            usable,
            identity,
            prior_for,
            whitelist_for,
            packs_for,
            now,
            stale_after,
        )
    except DATABASE_ERRORS:
        raise
    except Exception:  # noqa: BLE001 - the band it read must not be lost to odd stored data
        return replace(headline, doubts=("part of its analysis couldn't be worked out",))


def _with_details(
    store, headline, found, usable, identity, prior_for, whitelist_for, packs_for, now, stale_after
) -> FleetHost:
    host, row, after = headline.host, found.row, found.after
    reasons: list[str] = []
    whitelist = None
    # A removed host has no group or settings of its own now, so comparing with
    # them would call it out of date until it is purged.
    check_whitelist = whitelist_for is not None and not headline.removed
    if check_whitelist:
        try:
            whitelist = whitelist_for(host)
        except Exception:  # noqa: BLE001 - one broken file mustn't hide the others' results
            check_whitelist = False
            reasons.append("its whitelist can't be read")
    packs, problems = packs_for(host) if packs_for else (None, None)
    analyse, rescore = out_of_date(
        after,
        prior_for(host) if prior_for and not headline.removed else None,
        whitelist,
        packs,
        problems,
        check_packs=packs_for is not None,
        check_whitelist=check_whitelist,
    )
    reasons += [*analyse, *rescore]
    # A whitelist rule expiring, say, can turn this Low into a High in the report.
    # Only a newer tool's checks stay out: an upgrade shouldn't alarm the whole fleet.
    doubts = [reason for reason in reasons if reason != OLDER_CHECKS]
    if row["id"] != usable[-1]["id"]:
        reasons.insert(0, "a newer collection hasn't been analysed")
        doubts.append("a newer collection hasn't been analysed")
    if headline.last_failed:
        doubts.append(f"its last collection was {headline.last_failed[0]}")
    if row["status"] != "complete":
        modules = [g for g in _gaps(after) if g.startswith("module ")][:3]
        named = f" ({visible('; '.join(modules), 200)})" if modules else ""
        doubts.append(f"this collection was {row['status']}{named}")
    if not headline.removed and _old(row["started_at"], now, stale_after):
        doubts.append(f"collected more than {stale_after.days} days ago")
    memory = remembered(after) or {}
    if memory.get("failed"):
        doubts.append(f"checks that couldn't run: {visible(', '.join(memory['failed']), 200)}")

    earlier, earlier_why = (None, None)
    if len(store.assessments(row["id"])) > 1:
        earlier, earlier_why = _load(store, row["id"], identity, which=-2)
    previous = found.before or earlier
    older_than_after = [r for r in usable if r["started_at"] < row["started_at"]]
    before = None
    if previous is not None:
        before = remembered(previous)
        if found.before is not None:
            older = [r for r in usable if r["started_at"] < found.before_row["started_at"]]
        else:
            older = older_than_after
        before["exposed"] = _known_exposure(store, previous, older, identity)
    known = {_gap_kind(g) for g in _gaps(previous)}
    # Notes on what a pack or a check chose not to judge aren't the host hiding anything.
    new_gaps = [
        g
        for g in _gaps(after)
        if previous and _gap_kind(g) not in known and not g.startswith(_NOT_HIDING)
    ]
    blind = [g for g in _gaps(after) if g.startswith(_BLIND)]
    doubts += [visible(g, 200) for g in blind]
    # Part of what's looked at wasn't read, on any check: nothing "new" about it after the first.
    reduced = [g for g in _gaps(after) if _reduces_coverage(g)]
    doubts += [f"part of this server couldn't be read: {visible(g, 200)}" for g in reduced]
    fresh = [g for g in new_gaps if g not in blind and g not in reduced]
    if fresh:
        doubts.append(f"it can see less than before: {visible(fresh[0], 200)}")
    comparable = (
        row["status"] == "complete"
        and found.before is not None
        and found.before.get("versions") == after.get("versions")
        and found.before.get("packs") == after.get("packs")
        and found.before.get("packs_not_applied") == after.get("packs_not_applied")
        and not memory.get("failed")
        and not new_gaps
        and not blind
        and not reduced
    )
    resolved, suppressed, not_seen = _gone(before, after, comparable)
    rescored = _band_of(earlier)
    return replace(
        headline,
        exposed=_known_exposure(store, after, older_than_after, identity),
        unjudged=tuple(sorted(_exposed(after)[1])),
        doubts=tuple(doubts),
        out_of_date=tuple(reasons),
        first=before is None and not found.before_unreadable and not earlier_why,
        before_unreadable=before is None and (found.before_unreadable or bool(earlier_why)),
        band_before=_band_of(previous) if before else None,
        rescored_from=rescored if rescored != headline.band else None,
        changes=tuple(alerts(host, before, after)) if before else (),
        resolved=resolved,
        suppressed=suppressed,
        not_seen=not_seen,
    )


def serious(item: FleetHost) -> int:
    """High and critical findings in effect, of any category."""
    return sum(n for key, n in item.counts.items() if key.rpartition("/")[2] in SERIOUS)


def sort_key(item: FleetHost) -> tuple:
    if item.state == "unreadable":
        rank = _UNREADABLE
    elif item.band not in BANDS:
        rank = _UNKNOWN
    elif item.doubts and _ORDER[item.band] > _UNKNOWN:
        rank = _UNKNOWN  # reassuring, with nothing recent behind it
    else:
        rank = _ORDER[item.band]
    # Hygiene and exposure don't move the band, so a low score can hide serious
    # findings: those come first among the less worrying hosts.
    return (rank, -serious(item) if rank >= _UNKNOWN else 0, -(item.probability or 0), item.host)


def fleet(
    store,
    identity,
    groups: dict[str, str | None],
    prior_for=None,
    whitelist_for=None,
    packs_for=None,
    group: str | None = None,
    now: datetime | None = None,
    stale_after: timedelta = STALE_AFTER,
) -> list[FleetHost]:
    """Every host in the inventory or the store, most worrying first.
    `groups` is the inventory's name → group. A host no longer in the
    inventory has no group, so it shows under any filter: a removed host's
    bad result shouldn't be filtered out of sight. A store that can't answer,
    or a key that opens nothing, is an EvidenceError: it isn't about any one
    host, and calling each one tampered with would be wrong."""

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
                stale_after,
                removed=bool(groups) and name not in groups,
            )
        except DATABASE_ERRORS:
            raise
        except Exception:  # noqa: BLE001 - one host's odd data mustn't blank the fleet
            return FleetHost(name, groups.get(name), "unreadable", unreadable_why="internal")

    try:
        names = set(groups) | set(store.hosts())
        hosts = [one(n) for n in names if group is None or n not in groups or groups[n] == group]
    except DATABASE_ERRORS as exc:
        raise EvidenceError(store_unreadable(exc)) from exc
    unreadable = [h for h in hosts if h.state == "unreadable"]
    if (
        unreadable
        and all(h.unreadable_why == "key" for h in unreadable)
        and not any(h.state == "analysed" for h in hosts)
    ):
        raise EvidenceError(
            "no stored analysis can be decrypted with this evidence key: is it the right one?"
        )
    return sorted(hosts, key=sort_key)


@dataclass(frozen=True)
class _Settings:
    config: Any
    inventory: Any
    identity: Any
    found: tuple
    prior_for: Callable
    whitelist_for: Callable
    packs_for: Callable


def _settings(base: Path, identity_path: str | None = None) -> _Settings:
    from functools import partial

    from checker.assess import prior_for
    from checker.evidence import load_config, load_identity
    from checker.inventory import load_inventory
    from checker.packs.choice import for_host
    from checker.packs.store import in_force_read_only
    from checker.whitelist import for_host as whitelist_for_host

    config = load_config(base)
    path = identity_path or config.identity_file
    if not path:
        raise EvidenceError("no evidence key here")
    try:
        identity = load_identity(Path(path))
    except pyrage.IdentityError as exc:
        raise EvidenceError("the evidence key can't be read: it isn't a key") from exc
    inventory = load_inventory()
    found = in_force_read_only(base, config.packs.trusted_keys)
    return _Settings(
        config,
        inventory,
        identity,
        found,
        partial(prior_for, config=config, inventory=inventory),
        lambda name: whitelist_for_host(base, name, inventory),
        partial(for_host, config=config, inventory=inventory, found=found),
    )


def read_fleet(
    base: Path, identity_path: str | None = None, group: str | None = None
) -> tuple[list[FleetHost], list[str]]:
    """The fleet from a home's settings, and why any threat pack isn't applied. Opens
    the store read-only; the command and the web interface both come through here."""
    from checker.evidence import Store, database_file

    settings = _settings(base, identity_path)
    store = Store(database_file(base), read_only=True)
    try:
        hosts = fleet(
            store,
            settings.identity,
            {h.name: h.group for h in settings.inventory.hosts},
            settings.prior_for,
            settings.whitelist_for,
            settings.packs_for,
            group,
            stale_after=timedelta(days=settings.config.stale_after_days),
        )
    finally:
        store.close()
    return hosts, settings.found[1]


def _stored_advice(store, host: str, identity, found: _Found) -> dict:
    """What the AI advisor last said about this host, as stored. Nothing asks it anything."""
    from checker.advisor.advise import latest_advice

    if found.row is None or found.after is None:
        return {}
    try:
        return latest_advice(store, host, identity, found.row["id"], found.after.get("analysed_at"))
    except DATABASE_ERRORS:
        raise
    except Exception:  # noqa: BLE001 - advice is extra: the findings still show, and say so
        return {"unreadable": True}


def read_host(base: Path, host: str) -> tuple | None:
    """One host's line in the fleet, its latest readable analysis, what the AI advisor said
    and whether it's on; or None if neither
    the inventory nor the store has heard of it: a name from a URL goes no further."""
    from checker.evidence import Store, database_file

    settings = _settings(base)
    store = Store(database_file(base), read_only=True)
    try:
        groups = {h.name: h.group for h in settings.inventory.hosts}
        try:
            if host not in groups and host not in store.hosts():
                return None
            try:
                item = fleet_host(
                    store,
                    host,
                    settings.identity,
                    groups.get(host),
                    settings.prior_for,
                    settings.whitelist_for,
                    settings.packs_for,
                    stale_after=timedelta(days=settings.config.stale_after_days),
                    removed=bool(groups) and host not in groups,
                )
            except DATABASE_ERRORS:
                raise
            except Exception:  # noqa: BLE001 - as in fleet(): loud, and the page still loads
                item = FleetHost(host, groups.get(host), "unreadable", unreadable_why="internal")
            assessment = None
            advice: dict = {}
            if item.state == "analysed":
                found = _analyses(store, usable_bundles(store, host), settings.identity)
                assessment = found.after
                advice = _stored_advice(store, host, settings.identity, found)
        except DATABASE_ERRORS as exc:
            raise EvidenceError(store_unreadable(exc)) from exc
    finally:
        store.close()
    return item, assessment, advice, settings.config.advisor.enabled


def read_threats(base: Path) -> dict:
    """The threat packs in force, each with how it touches each host, from what is stored."""
    from checker.packs.store import retired

    hosts, problems = read_fleet(base)
    settings = _settings(base)
    return {
        "packs": settings.found[0],
        "hosts": hosts,
        "applies": {h.host: {p.id for p in settings.packs_for(h.host)[0]} for h in hosts},
        "problems": problems,
        "retired": retired(base),
    }


def read_evidence(base: Path, host: str) -> dict | None:
    """What a host's latest readable analysis rests on, from what is stored: nothing is
    parsed or written, so what isn't stored is said to be missing (the next run stores it).
    None if the tool hasn't heard of the host."""
    from checker.analysis import load_events
    from checker.evidence import Store, database_file

    settings = _settings(base)
    store = Store(database_file(base), read_only=True)
    try:
        groups = {h.name for h in settings.inventory.hosts}
        try:
            if host not in groups and host not in store.hosts():
                return None
            found = _analyses(store, usable_bundles(store, host), settings.identity)
            if found.after is None or found.newest_unreadable:
                return {
                    "assessment": None,
                    "row": None,
                    "events": None,
                    "snapshot": None,
                    "baselines": {},
                    "custody": [],
                }
            row, after = found.row, found.after
            try:
                parsed = load_events(store, row, settings.identity)
            except EvidenceError:
                parsed = None  # damaged: said on the page, like details not stored
            baselines = {}
            for finding in _in_effect(after):
                refs = finding.get("evidence")
                for ref in refs if isinstance(refs, list) else []:
                    change = ref.get("change") if isinstance(ref, dict) else None
                    against = change[0] if isinstance(change, list) and change else None
                    if isinstance(against, str) and against not in baselines:
                        baselines[against] = _snapshot_or_none(store, against, settings.identity)
            return {
                "assessment": after,
                "row": dict(row),
                "events": parsed.events if parsed else None,
                "snapshot": _snapshot_or_none(store, row["id"], settings.identity),
                "baselines": baselines,
                "custody": [dict(c) for c in store.custody_of(row["id"])],
            }
        except DATABASE_ERRORS as exc:
            raise EvidenceError(store_unreadable(exc)) from exc
    finally:
        store.close()


def _snapshot_or_none(store, bundle_id: str, identity):
    """A collection's snapshot, if it is still stored and sound: otherwise the page says so."""
    from checker.analysis import load_snapshot

    try:
        return load_snapshot(store, store.bundle(bundle_id), identity)
    except EvidenceError:
        return None

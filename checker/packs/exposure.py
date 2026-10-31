"""Whether a host was exposed to a threat a pack describes (plan 4.3):
which affected packages it has, vulnerable or fixed by its distribution's
own version ordering, since when, and whether services still run code from
before the fix.

Rules (plans/phase4, 4.3):
- An installed package is judged by every pack entry it matches (its
  release, its binary name, the entry's `versions` pattern on the
  installed version); it is vulnerable if any of them says so.
- An installed version the family's parser refuses (the package database
  is the server's own, which an intruder can write) is "can't judge":
  reported, and counted as exposed for the prior, never as fixed.
- A fixed host was exposed from the window's start until, at the latest,
  the fixed version's install time. That is when the package was last
  installed or updated, so the fix may have come earlier (a later routine
  update moves it); with no package history in the evidence, the latest
  is what is known, and the exposure, and the prior's raise, are upper
  limits, said as such. The version before isn't in the evidence either,
  so it is taken to have been vulnerable.
- A process whose name matches the pack's stale-code patterns and that
  started before the fix was installed still runs the old code.
"""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from checker.packs.format import Pack
from checker.packs.versions import VersionError, compare

# os-release ID -> (pack release family, package manager)
FAMILIES = {
    "ubuntu": ("ubuntu", "dpkg"),
    "rhel": ("rhel", "rpm"),
    "rocky": ("rhel", "rpm"),
    "almalinux": ("rhel", "rpm"),
}
VULNERABLE, FIXED, CANT_JUDGE = "vulnerable", "fixed", "can't judge"
NOT_AFFECTED, NOT_COVERED, UNKNOWN_RELEASE = "not affected", "not covered", "unknown release"


@dataclass
class Judged:
    key: str  # its item in the snapshot's packages ("name arch")
    name: str
    version: str
    installed: str | None  # ISO time the installed version was installed
    status: str  # VULNERABLE, FIXED or CANT_JUDGE
    fixed: str | None  # the fix it was judged against (the deciding entry's)
    why: str = ""
    # For a fixed package: when the fix arrived, whether that is exact (the
    # package history says so), and whether it arrived as a first install
    # (nothing vulnerable before it).
    fixed_since: str | None = None
    exact: bool = False
    fresh: bool = False


@dataclass
class Exposure:
    pack_id: str
    pack_version: int
    likelihood_ratio: float
    release: str | None
    status: str
    packages: list[Judged] = field(default_factory=list)
    window_start: str = ""
    window_end: str | None = None
    exposed_from: str | None = None
    exposed_until: str | None = None  # None while still exposed
    share: float = 0.0  # of the window so far, 0..1
    fixed_at: str | None = None
    fix_time_exact: bool = False  # from the package history, not a last update's time
    removed_at: str | None = None  # a vulnerable package removed in the window, when
    stale: list[dict[str, Any]] = field(default_factory=list)  # processes still on old code
    mitigations: list[Any] = field(default_factory=list)  # checker.packs.mitigation.Judged

    def log_ratio(self) -> float:
        """What this exposure adds to the prior's log-odds (decision D3)."""
        return self.share * math.log(self.likelihood_ratio)


def release_of(host: dict[str, Any]) -> tuple[str | None, str | None]:
    """(pack release, package manager) from the snapshot's host facts."""
    os_facts = host.get("os") or {}
    family = FAMILIES.get(str(os_facts.get("id") or "").lower())
    version = str(os_facts.get("version_id") or "")
    if family is None or not version:
        return None, None
    name, manager = family
    if name == "ubuntu":
        return f"ubuntu:{version}", manager
    return f"rhel:{version.split('.')[0]}", manager


def _time(value: Any) -> datetime | None:
    """A time from the evidence, or None: a value out of range (a package
    database an intruder set to the year 30000) is not a time."""
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, UTC)
        parsed = datetime.fromisoformat(str(value))
    except (ValueError, OverflowError, OSError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _unepoched(version: str) -> str:
    head, sep, rest = version.partition(":")
    return rest if sep and head.isdigit() else version


def _matches(entry: Any, version: str) -> bool:
    """An entry's `versions` pattern against the installed version, with or
    without its epoch (packs write versions as vendors show them)."""
    if entry.versions is None:
        return True
    return any(fnmatch.fnmatchcase(v, entry.versions) for v in (version, _unepoched(version)))


# The vendor's own mark in a version: an entry without a `versions` pattern
# vouches as fixed only for a build that carries the same mark as its fix
# (a Remi or Sury build that sorts above the vendor's fix is someone else's
# numbering: "can't judge" unless an entry with a pattern covers it).
_VENDOR_MARKS = (re.compile(r"ubuntu"), re.compile(r"\.el\d+"))
_PROGRAM_VERSION = re.compile(r"\d+\.\d+")


def _vendor_mark(fixed: str) -> re.Pattern | None:
    return next((m for m in _VENDOR_MARKS if m.search(fixed)), None)


def judge(
    pack: Pack,
    host: dict[str, Any],
    packages: dict[str, dict[str, Any]],
    processes: list[dict[str, Any]],
    now: datetime,
    complete: bool = True,
    history: list[dict[str, Any]] | None = None,
    earlier: list[tuple[datetime, dict[str, dict[str, Any]]]] | None = None,
    history_complete: bool = False,
) -> Exposure:
    """The exposure of one host (its host facts, installed packages, and
    live processes, as collected at `now`) to one pack. `complete`: the
    package listing was collected whole; when it wasn't, finding nothing
    vulnerable proves nothing. `history`: the package changes the evidence
    holds ({"time", "type": "package.<action>", "fields"}), which date a
    fix exactly; `history_complete`: it was read whole (only then does a
    first install mean nothing was there before); `earlier`: earlier
    collections' package listings, with when they were collected, which
    bound it."""
    now = now if now.tzinfo else now.replace(tzinfo=UTC)
    window = pack.exposure
    start = window.window_start
    end = min(window.window_end, now) if window.window_end else now
    found = Exposure(
        pack.id,
        pack.version,
        window.likelihood_ratio,
        None,
        UNKNOWN_RELEASE,
        window_start=start.isoformat(),
        window_end=window.window_end.isoformat() if window.window_end else None,
    )
    release, manager = release_of(host)
    found.release = release or str((host.get("os") or {}).get("id") or "unknown")
    if release is None:
        return found
    entries = [e for e in window.packages if e.release == release]
    if not entries:
        found.status = NOT_COVERED
        return found
    for key, item in sorted(packages.items()):
        name = key.split(" ", 1)[0]
        version = str(item.get("version"))
        if item.get("manager") != manager:
            continue
        named = [e for e in entries if name in e.binary_names]
        matching = [e for e in named if _matches(e, version)]
        installed = _time(item.get("installed"))
        if named and not matching and window.other_builds == "cant_judge":
            found.packages.append(
                Judged(key, name, version[:100], installed.isoformat() if installed else None,
                       CANT_JUDGE, None, "a build from a repository the pack doesn't cover")
            )  # fmt: skip
        if not matching:
            continue
        found.packages.append(_judge_one(key, name, version, installed, matching, manager))
    history = sorted((h for h in history or [] if _time(h.get("time"))), key=lambda h: h["time"])
    statuses = {p.status for p in found.packages}
    # A vulnerable version removed in the window was exposed until then,
    # whatever is installed now.
    other_builds = window.other_builds
    removed = _removed(history, entries, manager, start, other_builds)
    if not statuses and complete:
        if removed is not None:
            # Not installed now, but a vulnerable version was until then.
            found.status, found.removed_at, found.fix_time_exact = FIXED, removed.isoformat(), True
            if end > start:
                until = min(removed, end)
                found.exposed_from, found.exposed_until = start.isoformat(), until.isoformat()
                found.share = (until - start).total_seconds() / (end - start).total_seconds()
            return found
    if VULNERABLE in statuses:
        found.status = VULNERABLE
    elif CANT_JUDGE in statuses or not complete:
        # A listing collected only in part could hide a vulnerable package.
        found.status = CANT_JUDGE
    elif FIXED in statuses:
        found.status = FIXED
    else:
        found.status = NOT_AFFECTED
        return found
    fixed = [p for p in found.packages if p.status == FIXED]
    for package in fixed:
        _arrival(package, history, earlier or [], entries, manager, history_complete, other_builds)
    # Every fixed package's time is needed: one unknown is a fix at an
    # unknown time. A package first installed already fixed, with nothing
    # vulnerable before it, extends no exposure.
    counted = [p for p in fixed if not p.fresh]
    times = [_time(p.fixed_since) for p in counted]
    fixed_at = max(times) if times and None not in times else (None if times else start)
    exact = bool(counted) and all(p.exact for p in counted)
    if removed is not None and fixed_at is not None and removed > fixed_at:
        fixed_at, exact = removed, True
        found.removed_at = removed.isoformat()
    found.fixed_at = fixed_at.isoformat() if fixed_at and fixed_at != start else None
    found.fix_time_exact = exact
    if fixed and found.status in (FIXED, CANT_JUDGE):
        # Old code: a service started before the newest of these arrived.
        found.stale = _stale(window, processes, fixed)
    if end <= start:
        return found  # the window hasn't opened yet at collection time
    span = (end - start).total_seconds()
    if found.status in (VULNERABLE, CANT_JUDGE) or fixed_at is None or found.stale:
        # Vulnerable, unknown, or a service still on the old code: exposed
        # through the window so far.
        found.exposed_from, found.share = start.isoformat(), 1.0
        return found
    if fixed_at > start:
        until = min(fixed_at, end)
        found.exposed_from, found.exposed_until = start.isoformat(), until.isoformat()
        found.share = min(1.0, (until - start).total_seconds() / span)
    return found


def _state(name: str, version: str | None, entries: list, manager: str, other_builds: str) -> str:
    """A version's standing against the pack: VULNERABLE, FIXED, CANT_JUDGE,
    or "absent" (removed, or not a version any entry covers, unless the pack
    counts such a build as one it can't judge)."""
    if version is None:
        return "absent"
    named = [e for e in entries if name in e.binary_names]
    matching = [e for e in named if _matches(e, version)]
    if not matching:
        return CANT_JUDGE if named and other_builds == "cant_judge" else "absent"
    return _judge_one("", name, version, None, matching, manager).status


def _events(history: list[dict[str, Any]], name: str, arch: str | None) -> list[dict[str, Any]]:
    return [
        h
        for h in history
        if (h.get("fields") or {}).get("name") == name
        and (arch is None or (h.get("fields") or {}).get("arch") in (None, arch, "all"))
    ]


def _uncertain(event: dict[str, Any]) -> bool:
    fields = event.get("fields") or {}
    return bool(fields.get("time_uncertain") or fields.get("zone_assumed"))


def _arrival(
    package: Judged,
    history: list,
    earlier: list,
    entries: list,
    manager: str,
    complete: bool,
    other_builds: str,
) -> None:
    """When a fixed package's fix arrived. The package history dates it
    exactly: the change into a fixed version after which it stayed fixed
    (a change whose `previous` was still vulnerable starts it again: a
    retried upgrade). Exact only if the last change found is to the version
    installed now (else changes are missing) and its time is certain. A
    first install of a fixed version extends no exposure only if the
    history is whole and shows nothing vulnerable before it, under any
    name. Without the history, the last install or update is the latest it
    can have been, earlier if an earlier collection had this very version."""
    parts = package.key.split(" ")
    arch = parts[1] if len(parts) > 1 else None
    since = None
    events = _events(history, package.name, arch)
    for event in events:
        fields = event.get("fields") or {}
        now = _state(package.name, fields.get("version"), entries, manager, other_builds)
        before = _state(package.name, fields.get("previous"), entries, manager, other_builds)
        if now != FIXED:
            since = None
        elif since is None or before in (VULNERABLE, CANT_JUDGE):
            since = event
    if since is not None and (events[-1].get("fields") or {}).get("version") == package.version:
        package.fixed_since = since["time"]
        package.exact = not _uncertain(since)
        package.fresh = (
            complete
            and since.get("type") == "package.install"
            and not (since.get("fields") or {}).get("previous")
            and not _vulnerable_before(
                history, earlier, entries, manager, since["time"], other_builds
            )
        )
        return
    latest = _time(package.installed)
    for collected, listing in earlier:
        before = (listing.get(package.key) or {}).get("version")
        # Only this very version: one changed since could have been
        # downgraded and fixed again in between.
        if (
            before == package.version
            and _state(package.name, before, entries, manager, other_builds) == FIXED
        ):
            if latest is None or collected < latest:
                latest = collected
    package.fixed_since = latest.isoformat() if latest else None


def _vulnerable_before(
    history: list, earlier: list, entries: list, manager: str, when: str, other_builds: str
) -> bool:
    """Whether anything the pack covers was still vulnerable (or couldn't be
    judged) just before `when`: the last change before it, under any name
    (dnf's obsoletes replace one name with another), left such a version
    installed; or an earlier collection listed one that no change since
    removed. (One removed before then is counted by _removed.)"""
    moment = _time(when)
    if moment is None:
        return True
    last: dict[str, str | None] = {}
    removed_at: dict[str, datetime] = {}
    for event in history:
        at = _time(event.get("time"))
        if at is None or at >= moment:
            continue
        fields = event.get("fields") or {}
        name = str(fields.get("name"))
        last[name] = fields.get("version")
        if fields.get("version") is None:
            removed_at[name] = at
    for name, version in last.items():
        if version and _state(name, str(version), entries, manager, other_builds) in (
            VULNERABLE,
            CANT_JUDGE,
        ):
            return True
    for collected, listing in earlier:
        if collected >= moment:
            continue
        for key, item in listing.items():
            name = key.split(" ", 1)[0]
            state = _state(name, str(item.get("version")), entries, manager, other_builds)
            gone = removed_at.get(name)
            if state in (VULNERABLE, CANT_JUDGE) and not (gone and gone > collected):
                return True
    return False


def _removed(
    history: list, entries: list, manager: str, start: datetime, other_builds: str
) -> datetime | None:
    """When the last vulnerable version an entry covers was removed in the
    window, if one was (the package history says so)."""
    removed = None
    for event in history:
        fields = event.get("fields") or {}
        if fields.get("version") is not None or event.get("type") not in (
            "package.remove",
            "package.purge",
        ):
            continue
        name, before = fields.get("name"), fields.get("previous")
        if before and _state(str(name), str(before), entries, manager, other_builds) in (
            VULNERABLE,
            CANT_JUDGE,
        ):
            when = _time(event.get("time"))
            if when is not None and when > start and (removed is None or when > removed):
                removed = when
    return removed


def _fix_time(names: set[str], fixed: list[Judged]) -> datetime | None:
    """When the fix a program runs on arrived: the newest of the fixed
    packages, or of its own version's where the program names one
    (php-fpm8.3 and php8.3-fpm: 8.4's fix says nothing of 8.3's workers).
    None when one of those times isn't known."""
    versions = {v for n in names for v in _PROGRAM_VERSION.findall(n)}
    own = [p for p in fixed if any(v in p.name for v in versions)]
    times = [_time(p.fixed_since) for p in own or fixed]
    return max(times) if times and None not in times else None


def _stale(window: Any, processes: list[dict[str, Any]], fixed: list[Judged]) -> list:
    """Processes matching the pack's stale-code patterns that started before
    the fix was (last) installed, or whose program file was replaced under
    them; with no known install time, only the latter."""
    patterns = window.stale_code.programs if window.stale_code else []
    found = []
    for process in processes:
        names = {
            str(process.get("comm") or ""),
            str(process.get("exe") or "").removesuffix(" (deleted)").rsplit("/", 1)[-1],
        }
        if not any(fnmatch.fnmatchcase(n, p) for n in names for p in patterns):
            continue
        started = _time(process.get("start_time"))
        replaced = bool(process.get("exe_deleted"))
        fixed_at = _fix_time(names, fixed)
        if replaced or (started is not None and fixed_at is not None and started < fixed_at):
            found.append(process)
    return found


def _judge_one(
    key: str, name: str, version: str, installed: datetime | None, entries: list, manager: str
) -> Judged:
    """One installed package against every entry it matches: vulnerable if
    any says so (an entry with no fix first); can't judge if its version
    can't be read, if its epoch is one the fix doesn't write, or if it
    sorts above a fix whose vendor's mark it doesn't carry."""
    when = installed.isoformat() if installed else None
    for entry in entries:
        if entry.fixed is None:
            return Judged(key, name, version, when, VULNERABLE, None, "no fix yet")
    decided, doubt = None, None
    for entry in entries:
        try:
            older = compare(manager, version, entry.fixed) < 0
        except VersionError as exc:
            return Judged(key, name, version[:100], when, CANT_JUDGE, entry.fixed, str(exc))
        if older:
            return Judged(key, name, version, when, VULNERABLE, entry.fixed)
        if _unepoched(version) != version and _unepoched(entry.fixed) == entry.fixed:
            doubt = doubt or (
                f"installed {version} has an epoch and the pack's fix {entry.fixed} doesn't:"
                " they can't be compared as written"
            )
        mark = _vendor_mark(entry.fixed) if entry.versions is None else None
        if mark is not None and not mark.search(version):
            doubt = doubt or (
                f"{version} isn't the vendor's own build (the fix {entry.fixed} is): a version"
                " from another repository needs its own entry"
            )
        decided = entry.fixed
    if doubt:
        return Judged(key, name, version, when, CANT_JUDGE, decided, doubt)
    return Judged(key, name, version, when, FIXED, decided)


def prior_raise(exposures: list[Exposure], cap: float) -> float:
    """The prior's log-odds raise from every pack's exposure, at most
    log(cap): several threats don't stack beyond what one may say."""
    return min(sum(e.log_ratio() for e in exposures), math.log(cap))

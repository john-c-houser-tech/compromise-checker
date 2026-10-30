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
    stale: list[dict[str, Any]] = field(default_factory=list)  # processes still on old code

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
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def judge(pack: Pack, host: dict[str, Any], packages: dict[str, dict[str, Any]],
          processes: list[dict[str, Any]], now: datetime) -> Exposure:  # fmt: skip
    """The exposure of one host (its host facts, installed packages and
    live processes, as collected at `now`) to one pack."""
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
    found.release = release
    if release is None:
        return found
    entries = [e for e in window.packages if e.release == release]
    if not entries:
        found.status = NOT_COVERED
        return found
    for key, item in sorted(packages.items()):
        name = key.split(" ", 1)[0]
        version = item.get("version")
        if item.get("manager") != manager:
            continue
        matching = [
            e for e in entries
            if name in e.binary_names
            and (e.versions is None or fnmatch.fnmatchcase(str(version), e.versions))
        ]  # fmt: skip
        if not matching:
            continue
        installed = _time(item.get("installed"))
        found.packages.append(_judge_one(key, name, version, installed, matching, manager))
    statuses = {p.status for p in found.packages}
    if VULNERABLE in statuses:
        found.status = VULNERABLE
    elif CANT_JUDGE in statuses:
        found.status = CANT_JUDGE
    elif FIXED in statuses:
        found.status = FIXED
    else:
        found.status = NOT_AFFECTED
        return found
    if end <= start:
        return found  # the window hasn't opened yet at collection time
    span = (end - start).total_seconds()
    if found.status in (VULNERABLE, CANT_JUDGE):
        found.exposed_from, found.share = start.isoformat(), 1.0
        return found
    times = [_time(p.installed) for p in found.packages]
    fixed_at = max((t for t in times if t is not None), default=None)
    if fixed_at is None:
        found.exposed_from, found.share = start.isoformat(), 1.0  # when unknown: exposed
        return found
    found.fixed_at = fixed_at.isoformat()
    if fixed_at > start:
        until = min(fixed_at, end)
        found.exposed_from, found.exposed_until = start.isoformat(), until.isoformat()
        found.share = min(1.0, (until - start).total_seconds() / span)
    patterns = window.stale_code.programs if window.stale_code else []
    for process in processes:
        started = _time(process.get("start_time"))
        names = {
            str(process.get("comm") or ""),
            str(process.get("exe") or "").removesuffix(" (deleted)").rsplit("/", 1)[-1],
        }
        if (
            started is not None
            and started < fixed_at
            and any(fnmatch.fnmatchcase(n, p) for n in names for p in patterns)
        ):
            found.stale.append(process)
    return found


def _judge_one(
    key: str, name: str, version: Any, installed: datetime | None, entries: list, manager: str
) -> Judged:
    """One installed package against every entry it matches: vulnerable if
    any says so; can't judge if its version can't be read."""
    when = installed.isoformat() if installed else None
    decided = None
    for entry in entries:
        if entry.fixed is None:
            return Judged(key, name, str(version), when, VULNERABLE, None, "no fix yet")
        try:
            older = compare(manager, version, entry.fixed) < 0
        except VersionError as exc:
            return Judged(key, name, str(version)[:100], when, CANT_JUDGE, entry.fixed, str(exc))
        if older:
            return Judged(key, name, str(version), when, VULNERABLE, entry.fixed)
        decided = entry.fixed
    return Judged(key, name, str(version), when, FIXED, decided)


def prior_raise(exposures: list[Exposure], cap: float) -> float:
    """The prior's log-odds raise from every pack's exposure, at most
    log(cap): several threats don't stack beyond what one may say."""
    return min(sum(e.log_ratio() for e in exposures), math.log(cap))

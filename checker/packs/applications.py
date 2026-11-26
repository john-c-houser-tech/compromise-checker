"""Applications a pack judges by a version folder in the web roots (plan
A.2, plans/application-exposure-plan-2026-11-26.md).

Rules:
- An install is a folder in a collected web root holding at least one folder
  that a pack's `folder` pattern matches (`redcap_v*`), followed by a digit,
  with a file inside it. Each install is judged on its own.
- Its running version is the newest version folder (decision 2). A folder
  whose name doesn't read as a dotted version makes the install "can't
  judge", never fixed: it could be the newest.
- A version is judged by the most specific entry whose `versions` glob
  matches it (decision 4): below `affected_from`, not affected; with no fix,
  or below the fix, vulnerable; else fixed. A line with no fix of its own
  falls to a broader entry and reads vulnerable, saying which fixes exist
  (decision 5).
- A fix arrived, at the latest, when the first fixed version folder's files
  were written (their earliest ctime), or when an earlier collection first
  listed it, whichever is earlier. It is never exact: a ctime moves with a
  later chmod or copy, and an unpacked folder may not have been running yet.
- A web root whose walk wasn't whole gives its installs "can't judge"
  unless every folder the packs name was walked whole first (decision 7);
  and while any web root's walk was cut short, another install may be in
  what wasn't walked, so the host as a whole is "can't judge" unless an
  install found is vulnerable.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from checker.packs.format import Application, dotted, specificity

VULNERABLE, FIXED, CANT_JUDGE = "vulnerable", "fixed", "can't judge"
NOT_AFFECTED = "not affected"
_DIGITS = tuple("0123456789")
# How deep below a web root an install is looked for when its walk was cut
# short (decision 8): /var/www/html/redcap-uat has its version folders at
# the third level. Deeper installs are said not to be seen.
INSTALL_DEPTH = 3


@dataclass
class Install:
    name: str  # "REDCap"
    path: str  # the install's folder: /var/www/html/redcap
    place: str | None  # the web root it was found in
    version: str  # the newest version folder's version
    status: str  # VULNERABLE, FIXED, CANT_JUDGE or NOT_AFFECTED
    fixed: str | None  # the deciding entry's fix
    why: str = ""
    folders: list[str] = field(default_factory=list)  # every version seen, oldest first
    evidence: str | None = None  # a file in the newest version folder (web_files item)
    fixed_since: str | None = None  # when the first fixed version folder arrived, at the latest
    walk_cut: bool = False  # can't judge only because its web root's walk was cut short


@dataclass
class WebEvidence:
    """What a collection says about the web roots."""

    files: dict[str, dict[str, Any]]  # web_files items, by path
    complete: bool  # the web_files section was collected whole
    # Per web root: {"whole": bool, "first_whole": bool | None}; None from a
    # collector before plan A.2, which then leaves only `complete`.
    walks: dict[str, dict[str, Any]] | None = None
    roots: list[str] | None = None  # the web roots the collector walked
    time_limit: bool = False  # the web roots' share of the time ran out
    earlier: list[tuple[datetime, dict[str, dict[str, Any]]]] = field(default_factory=list)


def patterns(packs: list[Any]) -> list[str]:
    """The `folder` patterns of the packs in force, for the collector to
    walk first (decision 7)."""
    found = {a.folder for p in packs for a in p.exposure.applications}
    return sorted(found)[:20]


def _prefix(app: Application) -> str:
    return app.folder[:-1]


def _versions(apps: list[Application], files: dict[str, dict[str, Any]]) -> dict:
    """{(name, folder, install): {version text: [file paths]}} for every
    file inside a folder a pack's pattern matches."""
    kinds = {(a.name, a.folder): _prefix(a) for a in apps}
    found: dict[tuple[str, str, str], dict[str, list[str]]] = {}
    for path, item in files.items():
        if item.get("type") != "-":
            continue
        parts = path.split("/")
        for i, part in enumerate(parts[:-1]):
            if i == 0:
                continue
            for (name, folder), prefix in kinds.items():
                # The version starts with a digit: redcap_vendor isn't a version folder.
                if part.startswith(prefix) and part[len(prefix) : len(prefix) + 1] in _DIGITS:
                    install = "/".join(parts[:i]) or "/"
                    key = (name, folder, install)
                    found.setdefault(key, {}).setdefault(part[len(prefix) :], []).append(path)
                    break
            else:
                continue
            break
    return found


def _decide(apps: list[Application], text: str) -> tuple[str, Application | None, str]:
    """One version's standing: (status, deciding entry, why)."""
    version = dotted(text)
    if version is None:
        return CANT_JUDGE, None, f"a version folder whose name isn't a version: {text[:60]!r}"
    matching = [a for a in apps if fnmatch.fnmatchcase(text, a.versions)]
    if not matching:
        return NOT_AFFECTED, None, ""
    top = max(specificity(a.versions) for a in matching)
    best = [a for a in matching if specificity(a.versions) == top]
    if len(best) > 1:  # a valid pack can't have this (format.Exposure)
        return CANT_JUDGE, None, f"{text}: two of the pack's entries match it equally"
    entry = best[0]
    if entry.affected_from and version < dotted(entry.affected_from):  # type: ignore[operator]
        return NOT_AFFECTED, entry, ""
    if entry.fixed is None:
        return VULNERABLE, entry, "no fix released yet"
    fix = dotted(entry.fixed)
    if version < fix:  # type: ignore[operator]
        if version[:2] != fix[:2]:  # type: ignore[index]
            fixes = sorted({a.fixed for a in apps if a.fixed}, key=dotted)
            line = ".".join(str(n) for n in version[:2])
            return VULNERABLE, entry, f"no fix on the {line} line; the fixes are {_listed(fixes)}"
        return VULNERABLE, entry, f"before the fix {entry.fixed}"
    return FIXED, entry, ""


def _listed(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _arrived(
    paths: list[str], files: dict[str, dict[str, Any]], folder: str, earlier: list
) -> datetime | None:
    """When a version folder arrived, at the latest."""
    from checker.packs.exposure import _time

    times = [t for t in (_time(files[p].get("ctime")) for p in paths) if t is not None]
    for collected, listing in earlier:
        if any(p.startswith(folder + "/") for p in listing):
            times.append(collected)
    return min(times) if times else None


def judge_installs(apps: list[Application], web: WebEvidence) -> tuple[list[Install], bool]:
    """Every install of the pack's applications, judged, and whether an
    install may be missing from what was collected."""
    installs = []
    by_name: dict[tuple[str, str], list[Application]] = {}
    for app in apps:
        by_name.setdefault((app.name, app.folder), []).append(app)
    found = _versions(apps, web.files)
    for (name, folder, path), versions in sorted(found.items()):
        entries = by_name[(name, folder)]
        prefix = folder[:-1]
        paths = next(iter(versions.values()))
        place = web.files[paths[0]].get("place")
        unread = [v for v in versions if dotted(v) is None]
        ordered = sorted((v for v in versions if dotted(v) is not None), key=dotted)
        newest = ordered[-1] if ordered else next(iter(versions))
        install = Install(
            name, path, place, newest, CANT_JUDGE, None,
            folders=ordered + sorted(unread),
            evidence=sorted(versions[newest])[0],
        )  # fmt: skip
        if not _walked(web, place, folder):
            root = f"the walk of {place}" if place else "the walk of its web root"
            install.why = f"{root} was cut short before its version folders were all seen"
            install.walk_cut = True
        elif unread:
            install.why = f"a version folder whose name isn't a version: {prefix}{unread[0][:60]}"
        else:
            status, entry, why = _decide(entries, newest)
            install.status, install.why = status, why
            install.fixed = entry.fixed if entry else None
            if status == FIXED:
                # The fix arrived with the first fixed version above every
                # vulnerable one: 16.0.49, then 17.3.9, then 17.3.10 was
                # exposed until 17.3.10 came.
                states = [_decide(entries, v)[0] for v in ordered]
                bad = [n for n, st in enumerate(states) if st not in (FIXED, NOT_AFFECTED)]
                last_bad = max(bad, default=-1)
                first = next(
                    v for n, v in enumerate(ordered) if n > last_bad and states[n] == FIXED
                )
                arrived = _arrived(versions[first], web.files, f"{path}/{prefix}{first}",
                                   web.earlier)  # fmt: skip
                install.fixed_since = arrived.isoformat() if arrived else None
        installs.append(install)
    folders = sorted({a.folder for a in apps})
    cut = any(i.walk_cut for i in installs)  # its own root's walk, whatever the others did
    return installs, cut or _maybe_missing(web, folders)


def _walked(web: WebEvidence, place: str | None, folder: str) -> bool:
    """Whether an install's version folders were all seen: its web root
    walked whole, or this pack's version folders walked first and whole
    (only patterns the collection was sent count: a pack added since
    wasn't walked first)."""
    if web.walks is None:
        return web.complete
    walk = web.walks.get(place or "")
    if not walk:
        return False
    first = walk.get("first_whole") and folder in (walk.get("first_patterns") or [])
    return bool(walk.get("whole") or first)


def _maybe_missing(web: WebEvidence, folders: list[str]) -> bool:
    """Whether an install may be in what wasn't walked: a web root cut
    short, unless the pack's version folders were walked first and whole,
    and every folder down to INSTALL_DEPTH below it was listed (decision 8),
    so any install near the top was found."""
    if web.walks is None:
        return not web.complete
    if web.time_limit:
        return True
    return any(
        not w.get("whole") and not _found_all(w, folders)
        for r, w in web.walks.items()
        if r in (web.roots or [])
    )


def _found_all(walk: dict[str, Any], folders: list[str]) -> bool:
    sent = walk.get("first_patterns") or []
    levels = walk.get("levels_whole")
    return (
        bool(walk.get("first_whole"))
        and all(f in sent for f in folders)
        and isinstance(levels, int)
        and levels >= INSTALL_DEPTH
    )


def shallow_roots(web: WebEvidence, folders: list[str]) -> list[str]:
    """Web roots cut short where installs were still all found near the
    top (for the coverage note: a deeper install wouldn't be)."""
    if web.walks is None:
        return []
    return sorted(
        r for r, w in web.walks.items()
        if r in (web.roots or []) and not w.get("whole") and _found_all(w, folders)
    )  # fmt: skip

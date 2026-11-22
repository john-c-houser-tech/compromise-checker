"""PAM modules checked against the distribution's own packages (#189, V.4 and V.7).

The step between a collection and its checks: for each file in a PAM
module directory (changed, added, and since V.7 unchanged), find the
package the server says owns it and the version the server says is
installed, fetch the distribution's signed copy (checker.verify) and
compare the file by path. The results are stored with the collection, so a
report rebuilt later gives the same answer without the network.

Every input is the server's claim, so the lookup is held to the baseline
(plan, "Held to the baseline" and "Finding the version"): the system and
release must be the baseline's, the owner the baseline's where it had
one, and the version exactly one installed package's. Anything else is
"not checked", with its reason, and the finding stays as it is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checker.packs.versions import VersionError, compare
from checker.snapshot import Snapshot
from checker.verify import Lookup, Verifier, package_paths
from checker.verify import compare as compare_file
from checker.verify.words import show

# 2: links checked by their target; 3: every module, not only changed; 4: an unchanged
# module whose owner changed is held to the baseline's owner (#217); 5: a module several
# packages list is checked against each of them
OFFICIAL_VERSION = 5
CHANGED_FIELDS = {"sha256", "content_sha256", "size", "inode", "link_target"}
# Outcomes where the signed package contradicts the server's file.
MISMATCHES = ("differs", "absent", "link")
SYSTEMS = {"ubuntu": "dpkg", "rocky": "rpm", "almalinux": "rpm", "rhel": "rpm"}
# The PAM module directories the collector walks (PAM_MODULE_DIRS), one or two
# levels down: /etc/security/ (configuration) is not one of them.
MODULE_PATH = re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?security/[^/]+(?:/[^/]+)?")


@dataclass
class Target:
    path: str
    how: str  # "added", "changed" or "unchanged"
    sha256: str | None  # a regular file's hash, or None for a link
    link_target: str | None = None  # a link's target (pam_unix_acct.so -> pam_unix.so)


def targets(
    snapshot: Snapshot, since_baseline: dict[str, Any] | None, every: bool = False
) -> list[Target]:
    """The PAM module files to check: added, or changed in content, since
    the baseline; with `every`, all the others too ("unchanged": a module
    swapped before the baseline was taken shows only this way). Regular
    files by their hash, links by their target (a package's update
    re-creates its links); directories aren't checked."""
    items = _items(snapshot, "pam")
    found = []
    if every:
        changed = set()
        if since_baseline is not None:
            diff = since_baseline.get("pam") or {}
            changed = set(diff.get("added") or {}) | set(diff.get("changed") or {})
        for path in items:
            if path not in changed and MODULE_PATH.fullmatch(path):
                target = _target(path, "unchanged", items)
                if target is not None:
                    found.append(target)
    if since_baseline is None:
        return sorted(found, key=lambda t: t.path)
    diff = since_baseline.get("pam") or {}
    for how, entries in (
        ("added", diff.get("added") or {}),
        ("changed", diff.get("changed") or {}),
    ):
        for path, fields in entries.items():
            if not MODULE_PATH.fullmatch(path):
                continue
            if how == "changed" and not CHANGED_FIELDS & set(fields or {}):
                if every:  # changed in mode or times only: checked as unchanged
                    target = _target(path, "unchanged", items)
                    if target is not None:
                        found.append(target)
                continue
            target = _target(path, how, items)
            if target is not None:
                found.append(target)
    return sorted(found, key=lambda t: t.path)


def _target(path: str, how: str, items: dict) -> Target | None:
    item = items.get(path) or {}
    sha256, link = item.get("sha256"), item.get("link_target")
    if isinstance(sha256, str) and len(sha256) == 64:
        return Target(path, how, sha256)
    if item.get("type") == "l" and isinstance(link, str) and link:
        return Target(path, how, None, link)
    return None


def verify_pam(
    snapshot: Snapshot,
    baseline: Snapshot | None,
    since_baseline: dict[str, Any] | None,
    verifier: Verifier,
    baseline_id: str | None,
    previous: Snapshot | None = None,
    previous_results: dict[str, Any] | None = None,
    reported: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """{"version", "baseline_id", "checked_at", "files": {path: result}}:
    each result has an "outcome" (matched, differs, absent, link, ghost or
    not_checked) and what it was checked against, or the reason it wasn't.
    A result marked "transient" failed on this machine's side (network,
    time, gpgv) and is asked again the next time a verifier is given."""
    files = {}
    asked: dict[Lookup, Any] = {}  # one package update changes many modules: ask once
    seen = _newest_seen(previous, previous_results)

    def package(lookup: Lookup):
        if lookup not in asked:
            asked[lookup] = verifier.package(lookup)
        return asked[lookup]

    # The last stored results (the baseline's own too), for what earlier
    # checks had found: each file (path and hash) once found not to be its
    # package's, kept from check to check whatever comes between (#217's
    # reviews), until that very file matches its package.
    last = reported if reported is not None else previous_results
    earlier_files = (last or {}).get("files") or {}
    mismatched = _mismatched(last)
    for target in targets(snapshot, since_baseline, every=True):
        try:
            files[target.path] = _check(target, snapshot, baseline, package, seen, previous)
        except Exception as exc:  # noqa: BLE001 - nothing the server sends may stop the step
            files[target.path] = {
                "outcome": "not_checked",
                "reason": f"couldn't check it: {type(exc).__name__}",
                "how": target.how,
                "sha256": target.sha256,
                **({"link_target": target.link_target} if target.link_target else {}),
            }
        _mark_reported(files[target.path], target, earlier_files.get(target.path), mismatched)
    return {
        "version": OFFICIAL_VERSION,
        "baseline_id": baseline_id,
        "checked_at": datetime.now(UTC).isoformat(),
        "files": files,
        "mismatched": {path: sorted(keys) for path, keys in sorted(mismatched.items()) if keys},
    }


MAX_MISMATCHED_PER_PATH = 20  # the server picks the hashes: kept bounded


def _key(sha256: Any, link_target: Any) -> str | None:
    if isinstance(sha256, str) and sha256:
        return sha256
    return f"link:{link_target}" if isinstance(link_target, str) and link_target else None


def _mismatched(last: dict[str, Any] | None) -> dict[str, set[str]]:
    """{path: the files (hash, or "link:" and target) found there not to be
    their package's}: those the last results carried, and their own."""
    found: dict[str, set[str]] = {}
    carried = (last or {}).get("mismatched")
    for path, keys in carried.items() if isinstance(carried, dict) else ():
        if isinstance(path, str) and isinstance(keys, list):
            found[path] = {k for k in keys if isinstance(k, str)}
    for path, result in ((last or {}).get("files") or {}).items():
        if isinstance(result, dict) and result.get("outcome") in MISMATCHES:
            key = _key(result.get("sha256"), result.get("link_target"))
            if isinstance(path, str) and key:
                found.setdefault(path, set()).add(key)
    return found


def _mark_reported(
    result: dict[str, Any], target: Target, earlier: Any, mismatched: dict[str, set[str]]
) -> None:
    """Marks a module whose very file an earlier check found wasn't its
    package's, when this check doesn't show it again: whatever the server
    changes in its records (owner, package list, version, release) to make
    it "not checked", or however it hides it for a check between, it stays
    reported. A match for that file clears it; a mismatch now is reported as
    such. `new_owner_change`: an owner change the last check hadn't seen."""
    same = (
        isinstance(earlier, dict)
        and earlier.get("sha256") == target.sha256
        and earlier.get("link_target") == target.link_target
    )
    if "owner_changed" in result:
        result["new_owner_change"] = not (same and "owner_changed" in earlier)
    key = _key(target.sha256, target.link_target)
    keys = mismatched.setdefault(target.path, set())
    outcome = result.get("outcome")
    if key is None:
        return
    if outcome in MISMATCHES:
        if key not in keys and len(keys) >= MAX_MISMATCHED_PER_PATH:
            keys.discard(sorted(keys)[0])
        keys.add(key)
    elif key in keys:
        if outcome == "matched":
            keys.discard(key)  # the package's own file for the version installed
        else:
            result["reported_before"] = True
            # The first check that doesn't show it again (later ones carry the mark).
            result["no_longer_shown"] = (
                same and earlier.get("outcome") in MISMATCHES
            ) or not isinstance(earlier, dict)


def _check(
    target: Target,
    snapshot: Snapshot,
    baseline: Snapshot | None,
    package,
    seen: dict[tuple[str, str], str] | None = None,
    previous: Snapshot | None = None,
) -> dict:
    # The hash (or link target) compared, so the checks can tell the result is
    # for this very file.
    base = {"how": target.how, "sha256": target.sha256}
    if target.link_target is not None:
        base["link_target"] = target.link_target

    def not_checked(reason: str) -> dict:
        return dict(base, outcome="not_checked", reason=reason)

    if baseline is None:
        if target.how != "unchanged":
            return not_checked("there is no baseline to hold the lookup to")
        # The first collection (or the baseline itself): held to itself. A
        # module that isn't its package's is so whatever the baseline says.
        baseline = snapshot
    system = _os(snapshot)
    if system is None:
        return not_checked("the collection doesn't say which system the server runs")
    system_id, release = system
    if system_id not in SYSTEMS:
        return not_checked(f"{show(system_id)} isn't covered")
    if _same_release(system) != _same_release(_os(baseline)):
        return not_checked("the system or its release isn't the baseline's")
    owner = _owner(snapshot, target.path)
    before = _owner(baseline, target.path)

    def against(claim: dict) -> dict:
        return _against(target, snapshot, baseline, package, seen, previous, base, before, claim)

    current_owners = snapshot.live.get("pam_owners")
    complete_now = isinstance(current_owners, dict) and current_owners.get("complete") is True
    if (
        target.how == "unchanged"
        and before is not None
        and not before.get("several")
        # No owner counts only when this collection recorded them all (a list
        # cut short, or not collected, says nothing about the paths it lacks).
        and ((owner is None and complete_now) or (owner is not None and owner.get("several"))
             or (owner is not None and not _same_owner(snapshot, owner, before)))
    ):  # fmt: skip
        # The content is the baseline's but the package records now name
        # another owner (or none, or several): rare when honest, and the way
        # to hide a module swapped before the baseline from this check
        # (#217). It is held to the baseline's owner instead.
        base["owner_changed"] = {"baseline": _who(before), "now": _who(owner) if owner else None}
        if owner is not None and owner.get("several"):
            base["owner_changed"]["now"] = "several"
        owner = before
    if owner is None:
        return not_checked("no owning package was recorded for it")
    if owner.get("several"):
        return _several(target, snapshot, baseline, owner, before, not_checked, against)
    if before is not None and not _same_owner(snapshot, owner, before):
        return not_checked("its owning package isn't the baseline's")
    return against(owner)


def _against(
    target: Target,
    snapshot: Snapshot,
    baseline: Snapshot,
    package,
    seen,
    previous,
    base: dict,
    before: dict | None,
    owner: dict,
) -> dict:
    """The lookup and comparison for one owner, once it is held to the
    baseline's."""
    system_id, release = _os(snapshot)

    def not_checked(reason: str) -> dict:
        return dict(base, outcome="not_checked", reason=reason)

    # The baseline's owners count only when it recorded all of them (a
    # collector before 0.1.4 recorded none; a list cut short can't vouch for
    # the paths it lacks).
    baseline_owners = baseline.live.get("pam_owners")
    owners_known = isinstance(baseline_owners, dict) and baseline_owners.get("complete") is True
    if before is None and target.how == "changed" and owners_known:
        return not_checked("no owning package was recorded for it at the baseline")
    if not _complete(snapshot, "packages"):
        return not_checked("the package list wasn't collected whole")
    installed = _installed(snapshot, owner)
    if installed is None:
        if "owner_changed" in base:
            return not_checked(
                "there isn't exactly one installed version of the baseline's owning package"
            )
        return not_checked("there isn't exactly one installed version of its package")
    _, version, arch = installed
    earlier = _installed(baseline, owner) if _complete(baseline, "packages") else None
    if earlier is not None and earlier[2] != arch:
        return not_checked("its package's architecture isn't the baseline's")
    owner_unknown = before is None and target.how == "changed"
    if owner_unknown and earlier is None:
        # The owner can't be compared, so a file that was there then is checked
        # only if its owning package was installed then too (an owner swap
        # points somewhere else).
        return not_checked("its owning package wasn't installed at the baseline")
    result: dict[str, Any] = dict(
        base,
        package=owner["package"],
        version=version,
        arch=arch,
        # The baseline's version (None: not known), and whether this one is
        # older (None: not known). Only False lets a change count as an update.
        baseline_version=earlier[1] if earlier else None,
        older_than_baseline=_older(system_id, version, earlier[1]) if earlier else None,
    )
    if owner_unknown:
        result["baseline_owner_unknown"] = True
    if target.how == "added" and earlier is None and _complete(baseline, "packages"):
        result["new_package"] = True  # not installed at the baseline: not an update
    # The newest version of this package seen since the baseline (its own, the
    # previous collection's, what that collection's results had seen): going
    # back below it is a downgrade too, though still newer than the baseline's.
    newest = _newest(
        system_id,
        [
            v
            for v in (
                version,
                earlier[1] if earlier else None,
                _previous_version(previous, owner, arch),
                (seen or {}).get((owner["package"], arch)),
            )
            if v
        ],
    )
    result["newest_seen"] = newest
    result["older_than_seen"] = _older(system_id, version, newest) if newest else None
    official = package(Lookup(system_id, release, owner["package"], version, arch))
    if official.cached:
        result["cached"] = True  # answered from this machine's cache, no download
    if not official.found:
        return dict(
            result, outcome="not_checked", reason=official.reason, transient=official.transient
        )
    if target.link_target is not None:
        outcome = _compare_link(official, target, _merged_dirs(snapshot))
    else:
        outcome = compare_file(official, target.path, target.sha256, _merged_dirs(snapshot))
    return dict(result, outcome=outcome, source=official.source, signer=official.signer)


def _claims(owner: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every package that lists the path (the collector sends them when
    there are several, from 0.1.5), the recorded owner first."""
    if owner is None:
        return []
    found = [owner]
    for claim in owner.get("claims") or ():
        if isinstance(claim, dict) and _who(claim) not in [_who(c) for c in found]:
            found.append(claim)
    return found


def _several(target, snapshot, baseline, owner, before, not_checked, against) -> dict:
    """A path more than one package lists: checked against each of them the
    baseline listed too (all of them at the first collection). The file is
    its package's when one of them ships it; a signed package that ships
    another file there, with none matching, is `differs`, as for one owner.
    A collector before 0.1.5 sent only one name: not checked."""
    claims = _claims(owner)
    if len(claims) < 2:
        return not_checked("more than one package lists it")
    held = _claims(before) if before is not None else claims
    results = [
        against(claim) for claim in claims if any(_same_owner(snapshot, claim, b) for b in held)
    ]
    outcomes = [r.get("outcome") for r in results]
    # A match vouches for the file; a different file in a signed package is a
    # mismatch whatever the others say; "no such file" needs every one to say so.
    wanted = ["matched", "differs", "link"]
    if results and "not_checked" not in outcomes:
        wanted += ["ghost", "absent"]  # a package that makes it on the server vouches for none
    for outcome in wanted:
        for result in results:
            if result.get("outcome") == outcome:
                return dict(result, several=[_who(c) for c in claims])
    reasons = sorted({str(r.get("reason") or r.get("outcome")) for r in results})
    return dict(
        not_checked("more than one package lists it, and none of them could be checked"
                    + (f" ({'; '.join(reasons)})" if reasons else "")),
        several=[_who(c) for c in claims],
        transient=any(r.get("transient") for r in results),
    )  # fmt: skip


def _compare_link(official, target: Target, merged: dict[str, str]) -> str:
    """A link matches when the package ships a link at that path to the
    same target: it then leads where the package's does (to a file that is
    checked in its own right)."""
    entries = [official.files[p] for p in package_paths(target.path, merged) if p in official.files]
    if not entries:
        return "absent"
    if all(e.get("ghost") for e in entries):
        return "ghost"
    return "matched" if any(e.get("link") == target.link_target for e in entries) else "differs"


def _newest_seen(previous: Snapshot | None, results: dict[str, Any] | None) -> dict:
    """{(package, arch): the newest version the previous collection's results had seen}."""
    found: dict[tuple[str, str], str] = {}
    for result in ((results or {}).get("files") or {}).values():
        if not isinstance(result, dict):
            continue
        package, arch = result.get("package"), result.get("arch")
        newest = result.get("newest_seen") or result.get("version")
        if isinstance(package, str) and isinstance(arch, str) and isinstance(newest, str):
            found[(package, arch)] = newest
    return found


def _previous_version(previous: Snapshot | None, owner: dict, arch: str) -> str | None:
    if previous is None or not _complete(previous, "packages"):
        return None
    installed = _installed(previous, owner)
    return installed[1] if installed and installed[2] == arch else None


def _newest(system_id: str, versions: list[str]) -> str | None:
    newest = None
    for version in versions:
        try:
            if newest is None or compare(SYSTEMS[system_id], version, newest) > 0:
                newest = version
        except VersionError:
            return None  # can't be ordered: not known
    return newest


def _older(system_id: str, version: str, earlier: str) -> bool | None:
    try:
        return compare(SYSTEMS[system_id], version, earlier) < 0
    except VersionError:
        return None


def _same_release(system: tuple[str, str] | None) -> tuple[str, str] | None:
    """What must stay the baseline's: Ubuntu's whole release (24.04), the
    major for rpm systems, whose minor moves with an ordinary update (9.5 to
    9.6) and which use the major alone for their keys and repositories."""
    if system is None:
        return None
    system_id, release = system
    return (system_id, release.split(".")[0]) if SYSTEMS.get(system_id) == "rpm" else system


def _merged_dirs(snapshot: Snapshot) -> dict[str, str]:
    merged = (snapshot.live.get("system_files_summary") or {}).get("merged_dirs")
    if not isinstance(merged, dict):
        return {}
    return {k: v for k, v in merged.items() if isinstance(k, str) and isinstance(v, str)}


def _items(snapshot: Snapshot | None, section: str) -> dict[str, dict[str, Any]]:
    found = snapshot.sections.get(section) if snapshot else None
    return found.items if found else {}


def _complete(snapshot: Snapshot, section: str) -> bool:
    found = snapshot.sections.get(section)
    return bool(found and found.complete)


def _os(snapshot: Snapshot) -> tuple[str, str] | None:
    os_item = _items(snapshot, "host").get("os") or {}
    system, release = os_item.get("id"), os_item.get("version_id")
    if isinstance(system, str) and isinstance(release, str) and system and release:
        return system, release
    return None


def _owner(snapshot: Snapshot, path: str) -> dict[str, Any] | None:
    owners = (snapshot.live.get("pam_owners") or {}).get("owners") or {}
    owner = owners.get(path)
    return owner if isinstance(owner, dict) and isinstance(owner.get("package"), str) else None


def _who(owner: dict[str, Any]) -> dict[str, Any]:
    """An owner as the results record it: package and architecture."""
    return {"package": owner.get("package"), "arch": owner.get("arch")}


def _same_owner(snapshot: Snapshot, owner: dict[str, Any], before: dict[str, Any]) -> bool:
    """The same package and architecture; or one of them names no
    architecture (dpkg's list moved between pkg.list and pkg:amd64.list with
    a Multi-Arch change) and both lead to the same installed package."""
    if _who(owner) == _who(before):
        return True
    if owner.get("package") != before.get("package") or (owner.get("arch") and before.get("arch")):
        return False
    now, then = _installed(snapshot, owner), _installed(snapshot, before)
    return now is not None and then is not None and now[0] == then[0]


def _installed(snapshot: Snapshot, owner: dict[str, Any]) -> tuple[str, str, str] | None:
    """(key, version, the package's architecture) of the one installed
    package the owner names: by name and architecture when the owner gives
    one, else the single entry with that name (dpkg names an architecture
    only for Multi-Arch: same packages)."""
    packages = _items(snapshot, "packages")
    name, arch = owner["package"], owner.get("arch")
    if arch:
        keys = [f"{name} {arch}"] if f"{name} {arch}" in packages else []
    else:
        keys = [k for k in packages if k.split(" ")[0] == name and len(k.split(" ")) == 2]
    if len(keys) != 1:
        return None
    key = keys[0]
    if (packages[key] or {}).get("duplicate"):
        return None  # two entries for one name and architecture (an interrupted dnf)
    version = (packages[key] or {}).get("version")
    if not isinstance(version, str) or not version:
        return None
    return key, version, key.split(" ", 1)[1]


def stored_is_current(
    stored: dict[str, Any] | None, baseline_id: str | None, retrying: bool = False
) -> bool:
    """Whether stored results stand: made against this baseline, and (when
    a verifier is at hand, `retrying`) with nothing that failed on this
    machine's side and is worth asking again."""
    version = stored.get("version") if isinstance(stored, dict) else None
    # A report rebuilt without a verifier keeps the results of an earlier
    # version (they judged the changed modules the same way); with one, only
    # the current version stands.
    usable = version == OFFICIAL_VERSION or (
        not retrying and isinstance(version, int) and 2 <= version < OFFICIAL_VERSION
    )
    if not (
        usable
        and stored.get("baseline_id") == baseline_id
        and isinstance(stored.get("files"), dict)
    ):
        return False
    return not (retrying and any(r.get("transient") for r in stored["files"].values()))


def summary(stored: dict[str, Any] | None) -> dict[str, Any]:
    """Counts by outcome, and the reasons for what wasn't checked."""
    counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    owner_unknown = transient = downloaded = 0
    unchanged: dict[str, int] = {}
    unchanged_reasons: dict[str, int] = {}
    for result in ((stored or {}).get("files") or {}).values():
        outcome = result.get("outcome", "not_checked")
        transient += bool(result.get("transient"))
        downloaded += outcome != "not_checked" and not result.get("cached")
        if result.get("how") == "unchanged":
            # Every module is checked (V.7); the counts and reasons stay the
            # changed ones', and the unchanged are counted apart.
            unchanged[outcome] = unchanged.get(outcome, 0) + 1
            # (One with an owner change, or reported before, is a finding.)
            named = "owner_changed" in result or result.get("reported_before")
            if outcome in ("not_checked", "ghost") and not named:
                reason = str(
                    result.get("reason") or "its package lists it as a file made on the server"
                )[:200]
                unchanged_reasons[reason] = unchanged_reasons.get(reason, 0) + 1
            continue
        counts[outcome] = counts.get(outcome, 0) + 1
        owner_unknown += bool(result.get("baseline_owner_unknown"))
        if outcome == "not_checked":
            reason = str(result.get("reason") or "")[:200]
            reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "counts": counts,
        "not_checked": reasons,
        "baseline_owner_unknown": owner_unknown,
        "transient": transient,
        "unchanged": unchanged,
        "unchanged_not_checked": unchanged_reasons,
        "downloaded": downloaded,
    }


def unreachable(assessment: dict[str, Any] | None) -> bool:
    """Whether this host's check found the distributions' servers out of
    reach: something failed on this machine's side and nothing was checked.
    A run then stops asking for its other hosts (they are checked next run)."""
    found = (assessment or {}).get("official_files") or {}
    # Answers from the cache need no network, so only what was downloaded
    # shows the servers in reach.
    return bool(found.get("transient")) and not found.get("downloaded")


class _NoDownloads:
    """A fetcher that downloads nothing: what is already cached still answers."""

    def get(self, url, limit, first=None):
        from checker.verify.fetch import FetchError

        raise FetchError("not asked: the distributions' servers were out of reach this run")


def verifier_for(
    settings: Any, home: Path, deadline: float | None = None, cached_only: bool = False
) -> Verifier | None:
    """The Verifier the settings ask for (`verify` in the configuration),
    or None when it is turned off. `cached_only`: answers only from what is
    already kept here (a run whose earlier host found the servers out of
    reach), its misses marked to be asked again."""
    if settings is None or not settings.enabled:
        return None
    from checker.verify import deb

    mirrors = {}
    if settings.rocky:
        mirrors["rocky"] = {"current": settings.rocky.rstrip("/") + "/{major}"}
    if settings.almalinux:
        mirrors["almalinux"] = {"current": settings.almalinux.rstrip("/") + "/{major}"}
    older = settings.older_versions
    return Verifier(
        home / "cache" / "official-files",
        fetcher=_NoDownloads() if cached_only else None,
        deadline=deadline if deadline is not None else settings.seconds_per_server,
        ubuntu_archive=settings.ubuntu_archive or deb.ARCHIVE,
        ubuntu_snapshot=deb.SNAPSHOT if older else None,
        launchpad=deb.LAUNCHPAD if older else None,
        lists_dir=home / "cache" / "signed-lists",
        rpm_mirrors=mirrors or None,
        vaults=older,
    )

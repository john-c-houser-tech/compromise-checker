"""Changed PAM modules checked against the distribution's own packages (#189, V.4).

The step between a collection and its checks: for each file in a PAM
module directory that changed or appeared since the baseline, find the
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

OFFICIAL_VERSION = 2  # 2: links checked by their target
CHANGED_FIELDS = {"sha256", "content_sha256", "size", "inode", "link_target"}
SYSTEMS = {"ubuntu": "dpkg", "rocky": "rpm", "almalinux": "rpm", "rhel": "rpm"}
# The PAM module directories the collector walks (PAM_MODULE_DIRS), one or two
# levels down: /etc/security/ (configuration) is not one of them.
MODULE_PATH = re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?security/[^/]+(?:/[^/]+)?")


@dataclass
class Target:
    path: str
    how: str  # "added" or "changed"
    sha256: str | None  # a regular file's hash, or None for a link
    link_target: str | None = None  # a link's target (pam_unix_acct.so -> pam_unix.so)


def targets(snapshot: Snapshot, since_baseline: dict[str, Any] | None) -> list[Target]:
    """The PAM module files to check: added, or changed in content, since
    the baseline: regular files by their hash, links by their target (a
    package's update re-creates its links); directories aren't checked."""
    if since_baseline is None:
        return []
    diff = since_baseline.get("pam") or {}
    items = _items(snapshot, "pam")
    found = []
    for how, entries in (
        ("added", diff.get("added") or {}),
        ("changed", diff.get("changed") or {}),
    ):
        for path, fields in entries.items():
            if not MODULE_PATH.fullmatch(path):
                continue
            if how == "changed" and not CHANGED_FIELDS & set(fields or {}):
                continue
            item = items.get(path) or {}
            sha256, link = item.get("sha256"), item.get("link_target")
            if isinstance(sha256, str) and len(sha256) == 64:
                found.append(Target(path, how, sha256))
            elif item.get("type") == "l" and isinstance(link, str) and link:
                found.append(Target(path, how, None, link))
    return sorted(found, key=lambda t: t.path)


def verify_pam(
    snapshot: Snapshot,
    baseline: Snapshot | None,
    since_baseline: dict[str, Any] | None,
    verifier: Verifier,
    baseline_id: str | None,
    previous: Snapshot | None = None,
    previous_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """{"version", "baseline_id", "checked_at", "files": {path: result}}:
    each result has an "outcome" (matched, differs, absent, link or
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

    for target in targets(snapshot, since_baseline):
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
    return {
        "version": OFFICIAL_VERSION,
        "baseline_id": baseline_id,
        "checked_at": datetime.now(UTC).isoformat(),
        "files": files,
    }


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
        return not_checked("there is no baseline to hold the lookup to")
    system = _os(snapshot)
    if system is None:
        return not_checked("the collection doesn't say which system the server runs")
    system_id, release = system
    if system_id not in SYSTEMS:
        return not_checked(f"{show(system_id)} isn't covered")
    if _same_release(system) != _same_release(_os(baseline)):
        return not_checked("the system or its release isn't the baseline's")
    owner = _owner(snapshot, target.path)
    if owner is None:
        return not_checked("no owning package was recorded for it")
    if owner.get("several"):
        return not_checked("more than one package lists it")
    # The baseline's owners count only when it recorded all of them (a
    # collector before 0.1.4 recorded none; a list cut short can't vouch for
    # the paths it lacks).
    baseline_owners = baseline.live.get("pam_owners")
    owners_known = isinstance(baseline_owners, dict) and baseline_owners.get("complete") is True
    before = _owner(baseline, target.path)
    if before is not None and (before.get("package"), before.get("arch")) != (
        owner.get("package"),
        owner.get("arch"),
    ):
        return not_checked("its owning package isn't the baseline's")
    if before is None and target.how == "changed" and owners_known:
        return not_checked("no owning package was recorded for it at the baseline")
    if not _complete(snapshot, "packages"):
        return not_checked("the package list wasn't collected whole")
    installed = _installed(snapshot, owner)
    if installed is None:
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
    if not official.found:
        return dict(
            result, outcome="not_checked", reason=official.reason, transient=official.transient
        )
    if target.link_target is not None:
        outcome = _compare_link(official, target, _merged_dirs(snapshot))
    else:
        outcome = compare_file(official, target.path, target.sha256, _merged_dirs(snapshot))
    return dict(result, outcome=outcome, source=official.source, signer=official.signer)


def _compare_link(official, target: Target, merged: dict[str, str]) -> str:
    """A link matches when the package ships a link at that path to the
    same target: it then leads where the package's does (to a file that is
    checked in its own right)."""
    entries = [official.files[p] for p in package_paths(target.path, merged) if p in official.files]
    if not entries:
        return "absent"
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
    if not (
        isinstance(stored, dict)
        and stored.get("version") == OFFICIAL_VERSION
        and stored.get("baseline_id") == baseline_id
        and isinstance(stored.get("files"), dict)
    ):
        return False
    return not (retrying and any(r.get("transient") for r in stored["files"].values()))


def summary(stored: dict[str, Any] | None) -> dict[str, Any]:
    """Counts by outcome, and the reasons for what wasn't checked."""
    counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    owner_unknown = transient = 0
    for result in ((stored or {}).get("files") or {}).values():
        outcome = result.get("outcome", "not_checked")
        counts[outcome] = counts.get(outcome, 0) + 1
        owner_unknown += bool(result.get("baseline_owner_unknown"))
        transient += bool(result.get("transient"))
        if outcome == "not_checked":
            reason = str(result.get("reason") or "")[:200]
            reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "counts": counts,
        "not_checked": reasons,
        "baseline_owner_unknown": owner_unknown,
        "transient": transient,
    }


def unreachable(assessment: dict[str, Any] | None) -> bool:
    """Whether this host's check found the distributions' servers out of
    reach: something failed on this machine's side and nothing was checked.
    A run then stops asking for its other hosts (they are checked next run)."""
    found = (assessment or {}).get("official_files") or {}
    counts = found.get("counts") or {}
    checked = sum(n for outcome, n in counts.items() if outcome != "not_checked")
    return bool(found.get("transient")) and not checked


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

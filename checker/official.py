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
from checker.verify import Lookup, Verifier
from checker.verify import compare as compare_file

OFFICIAL_VERSION = 1
CHANGED_FIELDS = {"sha256", "content_sha256", "size", "inode"}
SYSTEMS = {"ubuntu": "dpkg", "rocky": "rpm", "almalinux": "rpm", "rhel": "rpm"}
# The PAM module directories the collector walks (PAM_MODULE_DIRS), one or two
# levels down: /etc/security/ (configuration) is not one of them.
MODULE_PATH = re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?security/[^/]+(?:/[^/]+)?")


@dataclass
class Target:
    path: str
    how: str  # "added" or "changed"
    sha256: str


def targets(snapshot: Snapshot, since_baseline: dict[str, Any] | None) -> list[Target]:
    """The PAM module files to check: added, or changed in content, since
    the baseline; regular files only (a directory or link has no hash)."""
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
            sha256 = (items.get(path) or {}).get("sha256")
            if isinstance(sha256, str) and len(sha256) == 64:
                found.append(Target(path, how, sha256))
    return sorted(found, key=lambda t: t.path)


def verify_pam(
    snapshot: Snapshot,
    baseline: Snapshot | None,
    since_baseline: dict[str, Any] | None,
    verifier: Verifier,
    baseline_id: str | None,
) -> dict[str, Any]:
    """{"version", "baseline_id", "checked_at", "files": {path: result}}:
    each result has an "outcome" (matched, differs, absent, link or
    not_checked) and what it was checked against, or the reason it wasn't."""
    files = {}
    for target in targets(snapshot, since_baseline):
        files[target.path] = _check(target, snapshot, baseline, verifier)
    return {
        "version": OFFICIAL_VERSION,
        "baseline_id": baseline_id,
        "checked_at": datetime.now(UTC).isoformat(),
        "files": files,
    }


def _check(target: Target, snapshot: Snapshot, baseline: Snapshot | None, verifier) -> dict:
    def not_checked(reason: str) -> dict:
        return {"outcome": "not_checked", "reason": reason, "how": target.how}

    if baseline is None:
        return not_checked("there is no baseline to hold the lookup to")
    system = _os(snapshot)
    if system is None:
        return not_checked("the collection doesn't say which system the server runs")
    if system != _os(baseline):
        return not_checked("the system or its release isn't the baseline's")
    system_id, release = system
    if system_id not in SYSTEMS:
        return not_checked(f"{system_id} isn't covered")
    owner = _owner(snapshot, target.path)
    if owner is None:
        return not_checked("no owning package was recorded for it")
    if owner.get("several"):
        return not_checked("more than one package lists it")
    before = _owner(baseline, target.path)
    if before is not None and (before.get("package"), before.get("arch")) != (
        owner.get("package"),
        owner.get("arch"),
    ):
        return not_checked("its owning package isn't the baseline's")
    if not _complete(snapshot, "packages"):
        return not_checked("the package list wasn't collected whole")
    installed = _installed(snapshot, owner)
    if installed is None:
        return not_checked("there isn't exactly one installed version of its package")
    key, version, arch = installed
    earlier = _installed(baseline, owner)
    # A baseline from before owners were recorded (collector 0.1.3): the owner
    # can't be compared, so a file that was there then is checked only if its
    # owning package was installed then too (an owner swap points elsewhere).
    owner_unknown = _owners_recorded(baseline) is False
    if owner_unknown and target.how == "changed" and earlier is None:
        return not_checked("its owning package wasn't installed at the baseline")
    lookup = Lookup(system_id, release, owner["package"], version, arch)
    official = verifier.package(lookup)
    result: dict[str, Any] = {
        "how": target.how,
        "package": owner["package"],
        "version": version,
        "arch": arch,
    }
    if owner_unknown:
        result["baseline_owner_unknown"] = True
    if earlier is not None and earlier[1] != version:
        result["baseline_version"] = earlier[1]
        try:
            result["older_than_baseline"] = compare(SYSTEMS[system_id], version, earlier[1]) < 0
        except VersionError:
            result["older_than_baseline"] = None
    if not official.found:
        return dict(result, outcome="not_checked", reason=official.reason)
    merged = (snapshot.live.get("system_files_summary") or {}).get("merged_dirs") or {}
    outcome = compare_file(official, target.path, target.sha256, merged)
    return dict(result, outcome=outcome, source=official.source, signer=official.signer)


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


def _owners_recorded(snapshot: Snapshot) -> bool:
    return isinstance(snapshot.live.get("pam_owners"), dict)


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
    version = (packages[key] or {}).get("version")
    if not isinstance(version, str) or not version:
        return None
    return key, version, key.split(" ", 1)[1]


def stored_is_current(stored: dict[str, Any] | None, baseline_id: str | None) -> bool:
    return (
        isinstance(stored, dict)
        and stored.get("version") == OFFICIAL_VERSION
        and stored.get("baseline_id") == baseline_id
        and isinstance(stored.get("files"), dict)
    )


def summary(stored: dict[str, Any] | None) -> dict[str, Any]:
    """Counts by outcome, and the reasons for what wasn't checked."""
    counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    owner_unknown = 0
    for result in ((stored or {}).get("files") or {}).values():
        outcome = result.get("outcome", "not_checked")
        counts[outcome] = counts.get(outcome, 0) + 1
        owner_unknown += bool(result.get("baseline_owner_unknown"))
        if outcome == "not_checked":
            reason = str(result.get("reason") or "")[:200]
            reasons[reason] = reasons.get(reason, 0) + 1
    return {"counts": counts, "not_checked": reasons, "baseline_owner_unknown": owner_unknown}


def verifier_for(settings: Any, home: Path, deadline: float | None = None) -> Verifier | None:
    """The Verifier the settings ask for (`verify` in the configuration),
    or None when it is turned off."""
    if settings is None or not settings.enabled:
        return None
    from checker.verify import deb

    mirrors = {}
    if settings.rocky:
        mirrors["rocky"] = {"current": settings.rocky.rstrip("/") + "/{major}"}
    if settings.almalinux:
        mirrors["almalinux"] = {"current": settings.almalinux.rstrip("/") + "/{major}"}
    return Verifier(
        home / "cache" / "official-files",
        deadline=deadline if deadline is not None else settings.seconds_per_server,
        ubuntu_archive=settings.ubuntu_archive or deb.ARCHIVE,
        lists_dir=home / "cache" / "signed-lists",
        rpm_mirrors=mirrors or None,
    )

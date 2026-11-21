"""Checking server files against the distribution's own signed packages, off the server.

Issue #189 (plan: plans/pam-offserver-verify-plan-2026-11-21.md). With
root, an intruder can forge every record on a server, so a changed PAM
module can only be explained by evidence the server didn't supply: the
distribution's official package for the version the server claims, its
signature checked here with pinned keys, and the module's SHA-256
compared by path.

The server's claims (system, release, package, version, architecture) are
only used to find the package. A false claim finds nothing, or a package
whose file doesn't match; either way nothing is explained.

`Verifier.package` never raises: every failure is an `Official` with no
files and a reason, so a caller keeps the finding high and says why.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from checker.verify import deb, gpg, rpm
from checker.verify.fetch import Fetcher, FetchError, HttpFetcher
from checker.verify.words import show

CACHE_FORMAT = 1


@dataclass(frozen=True)
class Lookup:
    """What the server says: os-release's ID and VERSION_ID, the package,
    its version (rpm: [epoch:]version-release) and the package's own
    architecture (amd64 or all; x86_64 or noarch).

    Every field is the server's claim. A match proves only that the file
    is the distribution's genuine file for the package and version given
    here, so the caller has to hold system, release and architecture to
    what an earlier collection saw (plan, V.4/V.5)."""

    system: str
    release: str
    package: str
    version: str
    arch: str


@dataclass
class Official:
    """A package's files as the distribution signed them, or why not."""

    lookup: Lookup
    files: dict[str, dict] | None = None  # path -> {"sha256": hex} or {"link": target}
    source: str = ""
    signer: str = ""
    reason: str = ""
    cached: bool = field(default=False, compare=False)

    @property
    def found(self) -> bool:
        return self.files is not None


# Merged /usr: the pairs a package's path may be reported under instead.
ALIASES = {"/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib", "/lib64": "/usr/lib64"}


def package_paths(path: str, merged: dict[str, str]) -> list[str]:
    """The paths a server file may have in its package: itself, and, where
    the server reports that top folder merged, the same file under the
    other name. Only the fixed pairs in ALIASES count."""
    found = [path]
    for short, long in ALIASES.items():
        if merged.get(short) != long:
            continue
        if path.startswith(long + "/"):
            found.append(short + path[len(long) :])
        elif path.startswith(short + "/"):
            found.append(long + path[len(short) :])
    return found


def compare(official: Official, path: str, sha256: str, merged: dict[str, str]) -> str:
    """'matched', 'differs', 'absent' (the package has no such file) or
    'link' (the package ships a link there, so there is nothing to hash)."""
    if not official.found:
        raise ValueError("compare needs a package that was found")
    entries = [official.files[p] for p in package_paths(path, merged) if p in official.files]
    if not entries:
        return "absent"
    if any(e.get("sha256") == (sha256 or "").lower() for e in entries):
        return "matched"
    if all("link" in e for e in entries):
        return "link"
    return "differs"


class Verifier:
    """One verification run: shares downloaded signed lists between the
    servers it is asked about, and keeps verified results in `cache_dir`."""

    def __init__(
        self,
        cache_dir: Path | None,
        fetcher: Fetcher | None = None,
        deadline: float = 60.0,
        ubuntu_archive: str = deb.ARCHIVE,
        ubuntu_snapshot: str | None = deb.SNAPSHOT,
        launchpad: str | None = deb.LAUNCHPAD,
        rpm_mirrors: dict[str, dict] | None = None,
        lists_dir: Path | None = None,
    ):
        self.cache_dir = cache_dir
        self.fetcher = fetcher or HttpFetcher(deadline)
        self.ubuntu = deb.Ubuntu(
            self.fetcher, ubuntu_archive, ubuntu_snapshot or "", launchpad, lists_dir=lists_dir
        )
        self.rpm = rpm.Rpm(self.fetcher, rpm_mirrors)

    def package(self, lookup: Lookup) -> Official:
        try:
            return self._package(lookup)
        except Exception as exc:  # noqa: BLE001 - the contract: a reason, never an error
            return Official(lookup, reason=f"couldn't check it: {type(exc).__name__}: {exc}"[:300])

    def _package(self, lookup: Lookup) -> Official:
        cached = self._cached(lookup)
        if cached is not None:
            return cached
        if gpg.gpgv_path() is None:
            return Official(lookup, reason="gpgv isn't installed on the checker's machine")
        try:
            if lookup.system == "ubuntu":
                files, source, signer = self.ubuntu.files(
                    lookup.release, lookup.package, lookup.version, lookup.arch
                )
            elif lookup.system in rpm.SYSTEMS:
                files, source, signer = self.rpm.files(
                    lookup.system, lookup.release, lookup.package, lookup.version, lookup.arch
                )
            elif lookup.system == "rhel":
                return Official(lookup, reason="Red Hat's packages need a subscription to download")
            else:
                return Official(lookup, reason=f"{show(lookup.system)} isn't covered")
        except (deb.PackageError, rpm.PackageError) as exc:
            return Official(lookup, reason=str(exc))
        except FetchError as exc:
            return Official(lookup, reason=f"couldn't download: {exc}")
        official = Official(lookup, files, source, signer)
        self._keep(official)
        return official

    # --- The cache: verified results only, by system, release, package, version, arch

    def _path(self, lookup: Lookup) -> Path | None:
        if self.cache_dir is None:
            return None
        key = json.dumps(asdict(lookup), sort_keys=True).encode()
        return self.cache_dir / f"{hashlib.sha256(key).hexdigest()}.json"

    def _safe_folder(self) -> bool:
        """The cache folder is this user's and no one else can write to it:
        an entry there is believed without checking a signature again."""
        try:
            info = os.lstat(self.cache_dir)
        except (OSError, TypeError):
            return False
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )

    def _cached(self, lookup: Lookup) -> Official | None:
        path = self._path(lookup)
        if path is None or not self._safe_folder():
            return None
        try:
            if not os.path.isfile(path):
                return None
            data = json.loads(path.read_text())
            if data.get("format") != CACHE_FORMAT or data.get("lookup") != asdict(lookup):
                return None
            signer = str(data["signer"])
            if signer not in pinned_for(lookup.system, lookup.release):
                return None  # a key no longer pinned for this system: fetch again
            files = data["files"]
            if not isinstance(files, dict) or not all(
                isinstance(v, dict) and set(v) in ({"sha256"}, {"link"}) for v in files.values()
            ):
                return None
            return Official(lookup, files, str(data["source"]), signer, cached=True)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            return None

    def _keep(self, official: Official) -> None:
        path = self._path(official.lookup)
        if path is None:
            return
        data = {
            "format": CACHE_FORMAT,
            "lookup": asdict(official.lookup),
            "files": official.files,
            "source": official.source,
            "signer": official.signer,
        }
        temporary = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not self._safe_folder():
                return
            handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".part-")
            with os.fdopen(handle, "w") as out:
                json.dump(data, out)
            os.replace(temporary, path)
            temporary = None
        except OSError:
            pass  # a cache that can't be written only costs a download next time
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass


def pinned_for(system: str, release: str) -> set[str]:
    """The fingerprints a result for this system and release may be signed by."""
    if system == "ubuntu":
        names = deb.KEYS
    else:
        names = rpm.SYSTEMS.get(system, {}).get("keys", {}).get(release.split(".")[0], ())
    return {gpg.KEYS[name][0] for name in names if name in gpg.KEYS}

"""Ubuntu: a package's file hashes, from the archive's signed data only.

The chain (plan, "What is trusted"): `dists/<suite>/InRelease`, checked
with gpgv against Ubuntu's pinned key -> the `Packages.xz` hash in its
signed text -> the package's SHA256 line there -> the `.deb`'s hash -> each
file's SHA-256, read from the `.deb`'s data archive in memory.

A version that has dropped off the current lists is looked for in Ubuntu's
dated archive copies (snapshot.ubuntu.com), each with its own signed
InRelease. Launchpad's publishing history only helps choose the copy's
date: nothing Launchpad says is trusted.
"""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import posixpath
import stat
import tarfile
import tempfile
import time
import urllib.parse
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from checker.verify import gpg
from checker.verify.fetch import Fetcher
from checker.verify.words import show

try:  # Python 3.14 has zstd; before it, the backport (same interface)
    from compression import zstd
except ImportError:  # pragma: no cover - depends on the Python version
    from backports import zstd

KEYS = ("ubuntu-2018",)
CODENAMES = {"22.04": "jammy", "24.04": "noble", "26.04": "resolute"}
ARCHES = ("amd64",)  # arm64 (ports.ubuntu.com) isn't covered yet
COMPONENTS = ("main", "universe")
ARCHIVE = "https://archive.ubuntu.com/ubuntu"
SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu"
SNAPSHOTS_FROM = datetime(2023, 3, 1, tzinfo=UTC)  # the first dated copies (V.1)
LAUNCHPAD = "https://api.launchpad.net/1.0"
POCKETS = {"Release": "", "Updates": "-updates", "Security": "-security"}

MAX_INRELEASE = 4 * 1024 * 1024
MAX_INDEX = 64 * 1024 * 1024  # a compressed Packages file
MAX_INDEX_TEXT = 512 * 1024 * 1024
MAX_DEB = 64 * 1024 * 1024
MAX_COPIES = 6  # dated copies tried for one version
MAX_STREAMS = 64  # compressed streams one after another in one file
LISTS_MAX_AGE = 6 * 3600  # seconds the archive's InRelease is kept on disk
MAX_DATA = 512 * 1024 * 1024  # a .deb's unpacked data archive
MAX_LAUNCHPAD = 4 * 1024 * 1024


class PackageError(Exception):
    """The package couldn't be found or checked; the words say why."""


# --- Reading the formats ------------------------------------------------------------------


def release_hashes(signed: bytes, suite: str) -> dict[str, tuple[str, int]]:
    """{index file: (sha256, size)} from an InRelease's signed text, which
    has to name `suite` (so one suite's signed list can't stand in for
    another's)."""
    text = signed.decode("utf-8", "replace")
    fields, hashes, section = {}, {}, None
    for line in text.splitlines():
        if line.startswith(" "):
            if section == "SHA256":
                parts = line.split()
                if len(parts) == 3 and len(parts[0]) == 64 and parts[1].isdigit():
                    hashes[parts[2]] = (parts[0].lower(), int(parts[1]))
            continue
        name, _, value = line.partition(":")
        section = name
        fields[name] = value.strip()
    if fields.get("Suite") != suite:
        raise PackageError(f"the signed list is for {fields.get('Suite')!r}, not {suite}")
    return hashes


def decompress(data: bytes, name: str, cap: int) -> bytes:
    """`data` unpacked by its file name's ending, at most `cap` bytes out.
    Streams one after another (as xz and zstd allow, and Ubuntu's release
    lists have) are all unpacked, and zero padding after them is allowed;
    anything else after the end refuses the file, never cut short."""
    if name.endswith(".tar") or name == "data.tar":
        return data if len(data) <= cap else _too_large(name)
    if not name.endswith((".zst", ".xz", ".gz")):
        raise PackageError(f"unsupported compression: {name}")
    out, rest = [], data
    left = cap
    for _ in range(MAX_STREAMS):
        if left <= 0:
            _too_large(name)  # zlib reads a limit of 0 as none at all
        if name.endswith(".zst"):
            engine = zstd.ZstdDecompressor()
        elif name.endswith(".xz"):
            engine = lzma.LZMADecompressor()
        else:
            engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            piece = engine.decompress(rest, max_length=left)
        except (lzma.LZMAError, zstd.ZstdError, zlib.error) as exc:
            raise PackageError(f"{name} doesn't unpack: {exc}") from None
        if not engine.eof:
            if len(piece) < left:
                raise PackageError(f"{name} is cut short")
            _too_large(name)
        out.append(piece)
        left -= len(piece)
        rest = engine.unused_data
        # No stream starts with a zero byte: only padding does, so it is read once.
        if not rest or (rest[:1] == b"\0" and not rest.strip(b"\0")):
            return b"".join(out)
    raise PackageError(f"{name} has more streams than the limit")


def _too_large(name: str):
    raise PackageError(f"{name} unpacks to more than the limit")


@dataclass(frozen=True)
class Entry:
    package: str
    version: str
    arch: str
    filename: str
    sha256: str
    size: int


def packages_index(text: str) -> dict[tuple[str, str, str], Entry]:
    """{(package, version, arch): Entry} from a Packages file."""
    found = {}
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line.startswith((" ", "\t")):
                name, _, value = line.partition(":")
                fields[name] = value.strip()
        try:
            entry = Entry(
                fields["Package"],
                fields["Version"],
                fields["Architecture"],
                fields["Filename"],
                fields["SHA256"].lower(),
                int(fields["Size"]),
            )
        except (KeyError, ValueError):
            continue
        found[(entry.package, entry.version, entry.arch)] = entry
    return found


def ar_members(deb: bytes) -> dict[str, bytes]:
    """A .deb's members (an `ar` archive), strictly parsed."""
    if not deb.startswith(b"!<arch>\n"):
        raise PackageError("not a .deb")
    members, pos = {}, 8
    while pos < len(deb):
        head = deb[pos : pos + 60]
        if len(head) < 60 or head[58:60] != b"`\n":
            raise PackageError("a broken .deb member header")
        name = head[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(head[48:58].decode("ascii").strip())
        except ValueError:
            raise PackageError("a broken .deb member size") from None
        body = deb[pos + 60 : pos + 60 + size]
        if len(body) != size or name in members:
            raise PackageError("a truncated or repeated .deb member")
        members[name] = body
        pos += 60 + size + (size % 2)
    return members


def deb_files(deb: bytes) -> dict[str, dict]:
    """{absolute path: {"sha256": hex} or {"link": target}} for what the
    .deb's data archive holds, read in memory: nothing is written out, no
    link is followed, and a path that climbs out ("..") refuses the package."""
    members = ar_members(deb)
    names = [n for n in members if n.startswith("data.tar")]
    if len(names) != 1:
        raise PackageError("a .deb without exactly one data archive")
    blob = decompress(members[names[0]], names[0], MAX_DATA)
    files: dict[str, dict] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tar:
            for member in tar:
                path = _clean(member.name)
                if path is None:
                    continue
                if member.isfile():
                    handle = tar.extractfile(member)
                    files[path] = {"sha256": hashlib.sha256(handle.read()).hexdigest()}
                elif member.issym():
                    files[path] = {"link": member.linkname}
                elif member.islnk():
                    target = _clean(member.linkname)
                    if target in files:
                        files[path] = dict(files[target])
    except tarfile.TarError as exc:
        raise PackageError(f"the data archive doesn't read: {exc}") from None
    return files


def _clean(name: str) -> str | None:
    """'./usr/lib/x' -> '/usr/lib/x'; None for the top folder; refuses '..'."""
    if any(part == ".." for part in name.split("/")):
        raise PackageError(f"a path that climbs out of the package: {name[:200]}")
    if name.startswith("./"):
        name = name[2:]
    path = posixpath.normpath("/" + name.lstrip("/"))
    return None if path in ("/", "/.") else path


# --- Finding the package ------------------------------------------------------------------


class Ubuntu:
    """Looks packages up for one verification run; signed lists are kept
    for the run, and in `lists_dir` between runs, so a fleet's servers
    share them. What is kept on disk is the downloaded bytes, checked again
    (signature, hash) every time they are used: the folder is a cache, never
    trusted."""

    def __init__(
        self,
        fetcher: Fetcher,
        archive: str = ARCHIVE,
        snapshot: str = SNAPSHOT,
        launchpad: str | None = LAUNCHPAD,
        now: datetime | None = None,
        lists_dir: Path | None = None,
    ):
        self.fetcher = fetcher
        self.lists_dir = lists_dir
        self.archive = archive.rstrip("/")
        self.snapshot = snapshot.rstrip("/") if snapshot else None
        self.launchpad = launchpad.rstrip("/") if launchpad else None
        self.now = now or datetime.now(UTC)
        self._lists: dict[tuple[str, str, str], dict | None] = {}
        self._failed: dict = {}  # lists that failed this run: (base, suite, part) -> why
        self._releases: dict[tuple[str, str], tuple | None] = {}  # verified InRelease

    def files(self, release: str, package: str, version: str, arch: str):
        """(files, source address, signer) for the package, or PackageError.
        `arch` is the package's own architecture: amd64, or all."""
        codename = CODENAMES.get(release)
        if codename is None:
            uncovered = PackageError(f"Ubuntu {show(release)} isn't covered")
            uncovered.unlisted = ""  # the whole system: no sign about this package
            raise uncovered
        if arch not in ARCHES + ("all",):
            uncovered = PackageError(f"{show(arch)} isn't covered yet")
            uncovered.unlisted = "arch"  # honest for the server's own architecture
            raise uncovered
        if "+esm" in version:
            # Ubuntu Pro's Extended Security Maintenance: its packages are on
            # esm.ubuntu.com, behind a Pro token, signed with another key.
            raise PackageError(
                "an Ubuntu Pro (ESM) version: ESM packages need a Pro token to download, "
                "so the checker can't check them yet"
            )
        lists_arch = "amd64" if arch == "all" else arch  # "all" packages are in each list
        problems: list[str] = []
        suites = [codename + "-security", codename + "-updates", codename]
        hit = self._find([(self.archive, suites)], package, version, arch, lists_arch, problems)
        if hit is None and not problems and not self._listed(package):
            # In none of the current lists under any version (a vendor's or a
            # PPA's package): Launchpad and the dated copies aren't asked,
            # so its name isn't sent there.
            unknown = PackageError(f"{show(package)} isn't one of Ubuntu's packages")
            unknown.unlisted = "package"
            raise unknown
        if hit is None and self.snapshot:
            copies = self._copies(codename, package, version, lists_arch)
            hit = self._find(copies, package, version, arch, lists_arch, problems)
        if hit is None:
            why = f" ({problems[0]})" if problems else ""
            missing = PackageError(
                f"{show(package)} {show(version)} isn't in Ubuntu's archive{why}"
            )
            missing.transient = bool(problems)  # a list that failed: worth asking again later
            missing.unlisted = "version"
            raise missing
        base, entry, signer = hit
        if entry.size > MAX_DEB:
            raise PackageError(f"{entry.filename} is larger than the limit")
        deb = self.fetcher.get(f"{base}/{entry.filename}", MAX_DEB)
        if deb is None:
            raise PackageError(f"{entry.filename} is listed but not there")
        if len(deb) != entry.size or hashlib.sha256(deb).hexdigest() != entry.sha256:
            raise PackageError(f"{entry.filename} doesn't match the signed list")
        return deb_files(deb), f"{base}/{entry.filename}", signer

    def _find(self, places, package, version, arch, lists_arch, problems):
        """The first signed list holding the package: (base, Entry, signer).
        `main` in every place before `universe` (most of what is asked
        about is in main, and universe's lists are large). A list that
        can't be checked is skipped, its problem kept for the reason."""
        for component in COMPONENTS:
            for base, suites in places:
                for suite in suites:
                    try:
                        listed = self._list(base, suite, component, lists_arch)
                    except PackageError as exc:
                        problems.append(str(exc))
                        continue
                    if not listed:
                        continue
                    entries, signer = listed
                    entry = entries.get((package, version, arch))
                    if entry is not None:
                        return base, entry, signer
        return None

    def _listed(self, package: str) -> bool:
        """Whether any list loaded this run names the package, at any version."""
        for listed in self._lists.values():
            if listed and any(key[0] == package for key in listed[0]):
                return True
        return False

    def _list(self, base, suite, component, arch):
        key = (base, suite, f"{component}/{arch}")
        if key in self._failed:
            # Not asked again this run, but still a problem each time: a list
            # that failed mustn't read as one without the package (#224).
            raise PackageError(self._failed[key])
        if key not in self._lists:
            try:
                self._lists[key] = self._load(base, suite, component, arch)
            except PackageError as exc:
                self._failed[key] = str(exc)
                raise
        return self._lists[key]

    def _release(self, base, suite):
        """(index hashes, signer) of the suite's verified InRelease, once a run."""
        key = (base, suite)
        if key not in self._releases:
            try:
                return self._fetch_release(key, base, suite)
            except BaseException:
                self._releases.pop(key, None)  # failed: asked again, never "no such suite"
                raise
        return self._releases[key]

    def _fetch_release(self, key, base, suite):
        """The suite's InRelease, fetched and checked (or kept from before)."""
        self._releases[key] = None
        url = f"{base}/dists/{suite}/InRelease"
        # A dated copy never changes; the archive's lists are kept a few hours.
        fixed = bool(self.snapshot) and base.startswith(self.snapshot + "/")
        name = "inrelease-" + hashlib.sha256(url.encode()).hexdigest()[:40]
        kept = self._kept(name, None if fixed else LISTS_MAX_AGE, MAX_INRELEASE)
        if kept is not None:
            try:
                self._releases[key] = self._checked_release(kept, base, suite)
                return self._releases[key]
            except PackageError:
                self._forget(name)  # a kept copy that fails is fetched again, once
        release = self.fetcher.get(url, MAX_INRELEASE)
        if release is None:
            return None
        self._releases[key] = self._checked_release(release, base, suite)
        self._keep(name, release)  # kept only once it has checked out
        return self._releases[key]

    def _checked_release(self, release: bytes, base: str, suite: str):
        try:
            signed, signer = gpg.verify_clearsigned(release, KEYS)
        except gpg.SignatureError as exc:
            raise PackageError(f"{base}/dists/{suite}/InRelease: {exc}") from None
        return release_hashes(signed, suite), signer

    def _load(self, base, suite, component, arch):
        verified = self._release(base, suite)
        if verified is None:
            return None
        hashes, signer = verified
        name = f"{component}/binary-{arch}/Packages.xz"
        if name not in hashes:
            return None
        digest, size = hashes[name]
        # By hash first: a mirror part-way through an update still serves
        # the file this InRelease names under its hash.
        folder = f"{base}/dists/{suite}/{component}/binary-{arch}"
        data = self._kept(f"index-{digest}", None, MAX_INDEX)  # named by its hash: never stale
        if data is not None and (len(data) != size or hashlib.sha256(data).hexdigest() != digest):
            self._forget(f"index-{digest}")
            data = None
        if data is None:
            data = self.fetcher.get(f"{folder}/by-hash/SHA256/{digest}", MAX_INDEX)
            if data is None:
                data = self.fetcher.get(f"{base}/dists/{suite}/{name}", MAX_INDEX)
            if data is None or len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise PackageError(f"{base}/dists/{suite}/{name} doesn't match the signed list")
            self._keep(f"index-{digest}", data)
        text = decompress(data, name, MAX_INDEX_TEXT).decode("utf-8", "replace")
        return packages_index(text), signer

    def _kept(self, name: str, max_age: float | None, limit: int) -> bytes | None:
        """A regular file kept in lists_dir (no link followed, at most `limit`
        bytes), if there and (with max_age) fresh."""
        if self.lists_dir is None:
            return None
        try:
            fd = os.open(self.lists_dir / name, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                return None
            if max_age is not None and time.time() - info.st_mtime > max_age:
                return None
            if max_age is None:
                # Used: kept another UNUSED_FOR (prune.py). Not for a list
                # whose time is its age (the archive's InRelease).
                try:
                    os.utime(fd)
                except OSError:
                    pass  # only means it may be downloaded again
            with os.fdopen(fd, "rb") as handle:
                fd = None
                return handle.read(limit)
        except OSError:
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def _forget(self, name: str) -> None:
        if self.lists_dir is not None:
            try:
                os.unlink(self.lists_dir / name)
            except OSError:
                pass

    def _keep(self, name: str, data: bytes) -> None:
        if self.lists_dir is None:
            return
        temporary = None
        try:
            self.lists_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            handle, temporary = tempfile.mkstemp(dir=self.lists_dir, prefix=".part-")
            with os.fdopen(handle, "wb") as out:
                out.write(data)
            os.replace(temporary, self.lists_dir / name)
            temporary = None
        except OSError:
            pass  # only costs a download next time
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _copies(self, codename, package, version, arch):
        """[(dated copy's base, [suite])] that should hold the version,
        chosen from Launchpad's publishing history (a hint only)."""
        if not self.launchpad:
            return []
        query = urllib.parse.urlencode(
            {
                "ws.op": "getPublishedBinaries",
                "binary_name": package,
                "exact_match": "true",
                "version": version,
                "distro_arch_series": f"{self.launchpad}/ubuntu/{codename}/{arch}",
                "ws.size": "50",
            }
        )
        raw = self.fetcher.get(f"{self.launchpad}/ubuntu/+archive/primary?{query}", MAX_LAUNCHPAD)
        try:
            entries = json.loads(raw or b"{}").get("entries", [])
        except (ValueError, AttributeError, RecursionError):
            return []
        copies = []
        for item in entries if isinstance(entries, list) else []:
            when = copy_time(item, version, self.now)
            if when is None:
                continue
            suite = codename + POCKETS[item["pocket"]]
            base = f"{self.snapshot}/{when.strftime('%Y%m%dT%H%M%SZ')}"
            if (base, [suite]) not in copies:
                copies.append((base, [suite]))
        return copies[:MAX_COPIES]


def copy_time(item, version: str, now: datetime) -> datetime | None:
    """When a dated copy should still list this publishing of `version`:
    just before it was superseded (or now), if that is after it was
    published and inside the copies' range; None to skip it."""
    if not isinstance(item, dict) or item.get("binary_package_version") != version:
        return None
    if item.get("pocket") not in POCKETS:
        return None
    published = _when(item.get("date_published"))
    if published is None:
        return None
    ended = _when(item.get("date_superseded")) or _when(item.get("date_removed")) or now
    if ended <= SNAPSHOTS_FROM:
        return None
    when = min(ended, now) - timedelta(minutes=1)
    if when <= published or when < SNAPSHOTS_FROM:
        return None
    return when.replace(microsecond=0)


def _when(text) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)

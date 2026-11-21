"""Rocky Linux and AlmaLinux: a package's file hashes, from its own signed header.

The trust is the rpm's RSA header signature (signature tag 268), checked
with gpgv against the vendor's pinned key for that major release: the
header holds every file's SHA-256 (FILEDIGESTS). Only the header is
downloaded, with a range request (V.1: 72-124 KB instead of the package).
The header's name, version, release and architecture have to equal what
was asked for, so a header can't stand in for another package's.

Where to look is only a locator: the standard file name in BaseOS and
AppStream, in the current repositories and then the vault's repository
for each minor release.
"""

from __future__ import annotations

import re
import stat
import struct

from checker.verify import gpg
from checker.verify.fetch import Fetcher
from checker.verify.words import show

SYSTEMS = {
    "rocky": {
        "current": "https://dl.rockylinux.org/pub/rocky/{major}",
        "vault": "https://dl.rockylinux.org/vault/rocky/{minor}",
        "vault_list": "https://dl.rockylinux.org/vault/rocky/",
        "letter_folders": True,  # Packages/p/pam-...rpm
        "keys": {"9": ("rocky-9",), "10": ("rocky-10",)},
    },
    "almalinux": {
        "current": "https://repo.almalinux.org/almalinux/{major}",
        "vault": "https://vault.almalinux.org/{minor}",
        "vault_list": "https://vault.almalinux.org/",
        "letter_folders": False,  # Packages/pam-...rpm
        "keys": {"9": ("almalinux-9",), "10": ("almalinux-10",)},
    },
}
REPOS = ("BaseOS", "AppStream")
MIRROR_FIELDS = ("current", "vault", "vault_list")
ARCHES = ("x86_64", "noarch")

LEAD = 96
FIRST_FETCH = 256 * 1024
MAX_HEADER = 8 * 1024 * 1024
MAX_TAGS = 4096
MAX_LISTING = 1024 * 1024

# Header tags (rpmtag.h)
SIG_RSA = 268
NAME, VERSION, RELEASE, EPOCH, ARCH = 1000, 1001, 1002, 1003, 1022
FILEMODES, FILEDIGESTS, FILELINKTOS, FILEFLAGS = 1030, 1035, 1036, 1037
GHOST = 64  # RPMFILE_GHOST: listed but not shipped, so no digest
DIRINDEXES, BASENAMES, DIRNAMES = 1116, 1117, 1118
FILEDIGESTALGO = 5011
SHA256 = 8


class PackageError(Exception):
    """The package couldn't be found or checked; the words say why."""


# --- Reading a header ---------------------------------------------------------------------


class Header:
    """One rpm header structure, strictly bounds-checked."""

    def __init__(self, data: bytes, offset: int):
        if data[offset : offset + 4] != b"\x8e\xad\xe8\x01":
            raise PackageError("not an rpm header")
        if len(data) < offset + 16:
            raise PackageError("a truncated rpm header")
        count, size = struct.unpack(">II", data[offset + 8 : offset + 16])
        if count > MAX_TAGS or size > MAX_HEADER:
            raise PackageError("an rpm header larger than the limit")
        self.start = offset
        self.end = offset + 16 + 16 * count + size
        if len(data) < self.end:
            raise PackageError("a truncated rpm header")
        self.blob = data[offset : self.end]
        index = data[offset + 16 : offset + 16 + 16 * count]
        self.store = data[offset + 16 + 16 * count : self.end]
        self.tags = {}
        for i in range(count):
            tag, kind, where, n = struct.unpack(">IIII", index[16 * i : 16 * i + 16])
            if where > size:
                raise PackageError("an rpm header tag outside its data")
            self.tags[tag] = (kind, where, n)

    def binary(self, tag: int) -> bytes | None:
        if tag not in self.tags:
            return None
        kind, where, n = self.tags[tag]
        if kind != 7 or where + n > len(self.store):
            raise PackageError(f"rpm tag {tag} isn't binary data")
        return self.store[where : where + n]

    def strings(self, tag: int) -> list[str] | None:
        if tag not in self.tags:
            return None
        kind, where, n = self.tags[tag]
        if kind not in (6, 8, 9):
            raise PackageError(f"rpm tag {tag} isn't text")
        if kind == 6:
            n = 1
        parts = self.store[where:].split(b"\0", n)
        if len(parts) < n + 1:  # each of the n strings ends in a NUL inside the data
            raise PackageError(f"rpm tag {tag} runs past its data")
        return [p.decode("utf-8", "replace") for p in parts[:n]]

    def ints(self, tag: int) -> list[int] | None:
        if tag not in self.tags:
            return None
        kind, where, n = self.tags[tag]
        width = {3: 2, 4: 4}.get(kind)
        if width is None or where + width * n > len(self.store):
            raise PackageError(f"rpm tag {tag} isn't numbers")
        code = "H" if width == 2 else "I"
        return list(struct.unpack(f">{n}{code}", self.store[where : where + width * n]))

    def one(self, tag: int) -> str | None:
        values = self.strings(tag)
        return values[0] if values else None


def split_package(data: bytes) -> tuple[Header, Header]:
    """(signature header, main header) of an rpm's first bytes."""
    if len(data) < LEAD + 16 or data[:4] != b"\xed\xab\xee\xdb":
        raise PackageError("not an rpm")
    signature = Header(data, LEAD)
    main_at = (signature.end + 7) // 8 * 8
    return signature, Header(data, main_at)


def needed_bytes(data: bytes) -> int:
    """How many of the rpm's first bytes hold both headers, from what is
    already there (at least the lead and signature header)."""
    if len(data) < LEAD + 16 or data[:4] != b"\xed\xab\xee\xdb":
        raise PackageError("not an rpm")
    signature = Header(data, LEAD)
    main_at = (signature.end + 7) // 8 * 8
    if len(data) < main_at + 16:
        return main_at + 16
    count, size = struct.unpack(">II", data[main_at + 8 : main_at + 16])
    if count > MAX_TAGS or size > MAX_HEADER:
        raise PackageError("an rpm header larger than the limit")
    return main_at + 16 + 16 * count + size


def header_files(main: Header) -> dict[str, dict]:
    """{absolute path: {"sha256": hex}, {"link": target} or {"ghost": True}}
    from the header (a ghost: listed, not shipped)."""
    bases = main.strings(BASENAMES) or []
    if not bases:
        return {}
    if (main.ints(FILEDIGESTALGO) or [0])[0] != SHA256:
        raise PackageError("the package's file digests aren't SHA-256")
    dirs = main.strings(DIRNAMES) or []
    indexes = main.ints(DIRINDEXES) or []
    modes = main.ints(FILEMODES) or []
    digests = main.strings(FILEDIGESTS) or []
    links = main.strings(FILELINKTOS) or []
    flags = main.ints(FILEFLAGS) or [0] * len(bases)
    lists = (indexes, modes, digests, links, flags)
    if any(len(values) != len(bases) for values in lists):
        raise PackageError("the package's file lists don't agree")
    files = {}
    for base, index, mode, digest, link, flag in zip(bases, *lists, strict=True):
        if index >= len(dirs) or "/" in base or base in ("", ".", ".."):
            raise PackageError("a broken file entry in the package")
        path = dirs[index] + base
        if not path.startswith("/") or "/../" in path + "/":
            raise PackageError(f"an odd path in the package: {path[:200]}")
        if flag & GHOST:
            # Listed, not shipped: whatever is there was made on the server.
            # Kept as such, so it isn't mistaken for a file the package lacks.
            files[path] = {"ghost": True}
            continue
        if stat.S_ISREG(mode):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise PackageError(f"a file without a SHA-256 in the package: {path[:200]}")
            files[path] = {"sha256": digest}
        elif stat.S_ISLNK(mode):
            files[path] = {"link": link}
    return files


def check_header(data: bytes, keys, name: str, evr: str, arch: str):
    """(files, signer) if the header's signature is good and it is the
    package asked for; PackageError otherwise."""
    signature, main = split_package(data)
    signed = signature.binary(SIG_RSA)
    if signed is None:
        raise PackageError("the package has no header signature")
    try:
        signer = gpg.verify_detached(signed, main.blob, keys)
    except gpg.SignatureError as exc:
        raise PackageError(f"the package's header signature: {exc}") from None
    epoch, version, release = split_evr(evr)
    said_epoch = main.ints(EPOCH)
    said = (main.one(NAME), main.one(VERSION), main.one(RELEASE), main.one(ARCH))
    if said != (name, version, release, arch) or (said_epoch or [0])[0] != (epoch or 0):
        raise PackageError(f"the header is for {said}, not {name} {evr} {arch}")
    return header_files(main), signer


def split_evr(evr: str) -> tuple[int | None, str, str]:
    """'[epoch:]version-release' -> (epoch, version, release)."""
    epoch = None
    if ":" in evr:
        head, evr = evr.split(":", 1)
        if not head.isdigit():
            raise PackageError(f"an odd epoch: {head[:20]}")
        epoch = int(head)
    version, _, release = evr.rpartition("-")
    if not version or not release:
        raise PackageError(f"not version-release: {evr[:100]}")
    return epoch, version, release


# --- Finding the package ------------------------------------------------------------------


_SAFE = re.compile(r"[A-Za-z0-9._+~^-]+")


class Rpm:
    """Looks packages up for one verification run."""

    def __init__(
        self, fetcher: Fetcher, mirrors: dict[str, dict] | None = None, vaults: bool = True
    ):
        self.fetcher = fetcher
        self.vaults = vaults  # off: only the current repositories are asked
        self.systems = {}
        for name, config in SYSTEMS.items():
            given = (mirrors or {}).get(name, {})
            # A mirror setting changes addresses only: never the keys or the layout.
            urls = {k: v for k, v in given.items() if k in MIRROR_FIELDS and isinstance(v, str)}
            self.systems[name] = dict(config, **urls)
        self._minors: dict[str, list[str]] = {}

    def files(self, system: str, release: str, package: str, evr: str, arch: str):
        """(files, source address, signer) for the package, or PackageError."""
        config = self.systems.get(system)
        major = release.split(".")[0]
        if config is None or major not in config["keys"]:
            raise PackageError(f"{show(system)} {show(release)} isn't covered")
        if arch not in ARCHES:
            raise PackageError(f"{show(arch)} isn't covered yet")
        for part in (package, evr, arch):
            if not _SAFE.fullmatch(part.replace(":", "")):
                raise PackageError("an odd package name or version")
        _, version, rel = split_evr(evr)
        file = f"{package}-{version}-{rel}.{arch}.rpm"
        repo_arch = "x86_64"
        for root in self._roots(config, major, rel):
            for repo in REPOS:
                folder = f"{package[0].lower()}/" if config["letter_folders"] else ""
                url = f"{root}/{repo}/{repo_arch}/os/Packages/{folder}{file}"
                data = self.fetcher.get(url, MAX_HEADER, first=FIRST_FETCH)
                if data is None:
                    continue
                need = needed_bytes(data)
                if need > len(data):
                    if need > MAX_HEADER:
                        raise PackageError("the package's header is larger than the limit")
                    data = self.fetcher.get(url, MAX_HEADER, first=need)
                    if data is None or len(data) < need:
                        raise PackageError(f"{file}: the header was cut short")
                files, signer = check_header(data, config["keys"][major], package, evr, arch)
                return files, url, signer
        raise PackageError(f"{package} {evr} isn't in {system}'s repositories")

    def _roots(self, config, major, rel):
        """The current repositories, then the vault's minors: the one the
        release names first (el9_8.1 -> 9.8), then from the newest down."""
        yield config["current"].format(major=major)
        if not self.vaults:
            return
        minors = self._vault_minors(config, major)
        named = re.search(rf"\.el{major}_(\d+)", rel)
        if named and f"{major}.{named.group(1)}" in minors:
            first = f"{major}.{named.group(1)}"
            minors = [first] + [m for m in minors if m != first]
        for minor in minors:
            yield config["vault"].format(minor=minor)

    def _vault_minors(self, config, major):
        key = config["vault_list"] + major
        if key not in self._minors:
            listing = self.fetcher.get(config["vault_list"], MAX_LISTING) or b""
            found = set(re.findall(rf'href="({major}\.\d+)/"', listing.decode("ascii", "replace")))
            self._minors[key] = sorted(found, key=lambda m: int(m.split(".")[1]), reverse=True)
        return self._minors[key]

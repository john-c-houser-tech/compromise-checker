"""What a signed release of the tool is (installation plan I2): `release.json` says which files make
it up, with their hashes, and `release.json.minisig` is its signature by the release key. Everything
else follows from that one signature, so a file is trusted only through its hash here. The key is
kept offline and signs by hand (docs/releasing.md); nothing in this module signs or downloads
anything.

The release key is apart from the keys that sign threat packs: a stolen pack key mustn't be able to
change the tool. Packs teach it what to look for, while a release replaces its code.

This is for a tool that's already installed and trusted. It needs pydantic and cryptography, which a
new machine only gets from the very release being checked, so a first install has to check the
signature some other way before it runs anything from the release.

A good signature says the release key signed these files once. It doesn't say they're the newest, so
a caller says what it will accept (`newer_than`, `expected_version`). Nothing here can tell that a
newer release is being withheld."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    model_validator,
)

from checker.packs.signing import (
    MAX_SIGNATURE_BYTES,
    PublicKey,
    SignatureError,
    public_key,
    verify,
)

# NouriLoop LLC's release key (key id 341D1ADD02E941AB), also on nouriloop.com.
RELEASE_KEYS: tuple[str, ...] = ("RWSrQekC3RodNJBjEJsAevGCUsudzjSUpTcGCiIyE/Cj1ISXhnqZOx95",)

MANIFEST = "release.json"
SIGNATURE = "release.json.minisig"
REQUIREMENTS = "requirements.lock"
MAX_MANIFEST_BYTES = 64 * 1024
_CHUNK = 1024 * 1024
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class ReleaseError(Exception):
    """A release that can't be trusted; the message says why."""


def version_key(version: str) -> tuple[int, int, int]:
    """For comparing versions as numbers: as text, 0.10.0 would sort before 0.9.0."""
    if not _VERSION.fullmatch(version):
        raise ReleaseError(f"{version!r} isn't a version such as 1.2.3")
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _matches(pattern: re.Pattern, what: str):
    def check(text: str) -> str:
        if not pattern.fullmatch(text):
            raise ValueError(f"not a {what}")
        return text

    return AfterValidator(check)


def _real_date(text: str) -> str:
    if not _DATE.fullmatch(text):
        raise ValueError("not a date such as 2026-11-02")
    date.fromisoformat(text)
    return text


class ReleaseFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sha256: Annotated[str, _matches(_SHA256, "SHA-256 hash")]
    size: StrictInt = Field(ge=0)


class Manifest(BaseModel):
    """What the release key vouches for. Unknown fields are refused, so a newer format can't be read
    as if it meant only what this version understands."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: StrictInt = Field(alias="schema")
    version: Annotated[str, _matches(_VERSION, "version such as 1.2.3")]
    commit: Annotated[str, _matches(_COMMIT, "full commit hash")]
    published: Annotated[str, AfterValidator(_real_date)]
    prerelease: StrictBool
    security_fix: StrictBool
    files: dict[str, ReleaseFile]

    @model_validator(mode="after")
    def _whole(self) -> Manifest:
        if self.schema_version != 1:
            raise ValueError(f"format {self.schema_version} isn't one this version can read")
        for name in self.files:
            if not _FILE_NAME.fullmatch(name) or name in (MANIFEST, SIGNATURE):
                raise ValueError(f"{name!r} isn't a plain file name for a release file")
        if self.wheel_name not in self.files:
            raise ValueError(f"it doesn't list {self.wheel_name}")
        if REQUIREMENTS not in self.files:
            raise ValueError(f"it doesn't list {REQUIREMENTS}")
        return self

    @property
    def wheel_name(self) -> str:
        return wheel_name(self.version)


def wheel_name(version: str) -> str:
    return f"checker-{version}-py3-none-any.whl"


def release_keys() -> list[PublicKey]:
    return [public_key(text) for text in RELEASE_KEYS]


def read_manifest(data: bytes, signature: bytes, keys: list[PublicKey] | None = None) -> Manifest:
    """A release's manifest, its signature checked before any of it is read."""
    keys = release_keys() if keys is None else keys
    if not keys:
        raise ReleaseError("this version of the tool has no release key to check against")
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError(f"{MANIFEST} is too large")
    try:
        verify(data, signature, keys)
    except SignatureError as exc:
        raise ReleaseError(f"{MANIFEST}: {exc}") from None
    try:
        return Manifest.model_validate(json.loads(data))
    except (ValueError, ValidationError) as exc:
        raise ReleaseError(f"{MANIFEST} can't be read: {exc}") from None


def _open_plain(path: Path) -> int:
    """One descriptor for a plain file: everything said about it is then about the same file, even
    if the name is swapped meanwhile. Links are refused, and a pipe can't hang the caller."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"{path.name} is missing, or isn't a plain file: {exc}") from None
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ReleaseError(f"{path.name} is missing, or isn't a plain file")
    return descriptor


def _read_small(path: Path, limit: int) -> bytes:
    with os.fdopen(_open_plain(path), "rb") as source:
        try:
            data = source.read(limit + 1)
        except OSError as exc:
            raise ReleaseError(f"can't read {path.name}: {exc}") from None
    if len(data) > limit:
        raise ReleaseError(f"{path.name} is too large")
    return data


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _check_one(path: Path, expected: ReleaseFile, sink: Callable[[bytes], object] | None) -> None:
    """Hash what's read from one descriptor, handing the same bytes to `sink` if there is one."""
    with os.fdopen(_open_plain(path), "rb") as source:
        if os.fstat(source.fileno()).st_size != expected.size:
            raise ReleaseError(f"{path.name} is the wrong size: it isn't the file that was signed")
        digest = hashlib.sha256()
        total = 0
        while True:
            try:
                chunk = source.read(_CHUNK)
            except OSError as exc:
                raise ReleaseError(f"can't read {path.name}: {exc}") from None
            if not chunk:
                break
            total += len(chunk)
            if total > expected.size:
                raise ReleaseError(f"{path.name} grew while it was being read")
            digest.update(chunk)
            if sink:
                sink(chunk)  # a failure here is the copy's, such as a full disk, not the source's
    if digest.hexdigest() != expected.sha256:
        raise ReleaseError(f"{path.name} has the wrong hash: it isn't the file that was signed")


def check_files(directory: Path, manifest: Manifest) -> None:
    """Every file the manifest lists is in `directory`, as it says. Files it doesn't list aren't
    part of the release and are never used, so they aren't looked at."""
    for name, expected in manifest.files.items():
        _check_one(directory / name, expected, None)


def _accept(manifest: Manifest, newer_than: str | None, expected_version: str | None) -> None:
    if expected_version is not None and manifest.version != expected_version:
        raise ReleaseError(f"this is version {manifest.version}, not {expected_version}")
    if newer_than is not None and version_key(manifest.version) <= version_key(newer_than):
        raise ReleaseError(f"version {manifest.version} isn't newer than {newer_than}")


def _read_signed(directory: Path) -> tuple[bytes, bytes]:
    return (
        _read_small(directory / MANIFEST, MAX_MANIFEST_BYTES),
        _read_small(directory / SIGNATURE, MAX_SIGNATURE_BYTES),
    )


def read_release(
    directory: Path,
    keys: list[PublicKey] | None = None,
    newer_than: str | None = None,
    expected_version: str | None = None,
) -> Manifest:
    """A whole release in `directory`: its signature, and then every file against its hash. This
    says what the files were when they were read. To install them, use `stage_release`."""
    data, signature = _read_signed(directory)
    manifest = read_manifest(data, signature, keys)
    _accept(manifest, newer_than, expected_version)
    check_files(directory, manifest)
    return manifest


def _sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_release(
    source: Path,
    target: Path,
    keys: list[PublicKey] | None = None,
    newer_than: str | None = None,
    expected_version: str | None = None,
) -> Manifest:
    """Copy a release from `source`, which someone less trusted may be able to write to, into a new
    private `target`, hashing each file as it's copied. What's in `target` is then what was checked,
    and is what to install from. `target` must not exist yet, and its parent must be writable only
    by the caller. It's put together beside `target` and moved there whole, so a stop at any moment
    (a service being stopped, a power cut) never leaves part of a release under that name."""
    data, signature = _read_signed(source)
    manifest = read_manifest(data, signature, keys)
    _accept(manifest, newer_than, expected_version)
    if os.path.lexists(target):
        raise ReleaseError(f"can't make {target}: it already exists")
    try:
        staged = Path(tempfile.mkdtemp(prefix=".stage-", dir=target.parent))
    except OSError as exc:
        raise ReleaseError(f"can't make {target}: {exc}") from None
    try:
        for name, expected in manifest.files.items():
            with (staged / name).open("xb") as copy:
                _check_one(source / name, expected, copy.write)
                copy.flush()
                os.fsync(copy.fileno())
        (staged / MANIFEST).write_bytes(data)
        (staged / SIGNATURE).write_bytes(signature)
        _sync(staged / MANIFEST)
        _sync(staged / SIGNATURE)
        _sync(staged)
        os.rename(staged, target)
        _sync(target.parent)
    except BaseException as exc:
        shutil.rmtree(staged, ignore_errors=True)
        if isinstance(exc, OSError):
            raise ReleaseError(f"can't copy the release: {exc}") from None
        raise
    return manifest

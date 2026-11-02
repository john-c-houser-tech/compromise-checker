"""What a signed release of the tool is (installation plan I2): `release.json` says which files make
it up, with their hashes, and `release.json.minisig` is its signature by the release key. Everything
else follows from that one signature, so a file is trusted only through its hash here. The key is
kept offline and signs by hand (docs/releasing.md); nothing in this module signs or downloads
anything.

The release key is apart from the keys that sign threat packs: a stolen pack key mustn't be able to
change the tool. Packs teach it what to look for, while a release replaces its code."""

from __future__ import annotations

import hashlib
import json
import re
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

from checker.packs.signing import PublicKey, SignatureError, public_key, verify

# NouriLoop LLC's release key. Empty until it's made, and then nothing can be trusted by accident.
RELEASE_KEYS: tuple[str, ...] = ()

MANIFEST = "release.json"
SIGNATURE = "release.json.minisig"
REQUIREMENTS = "requirements.lock"
MAX_MANIFEST_BYTES = 64 * 1024
_CHUNK = 1024 * 1024
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ReleaseError(Exception):
    """A release that can't be trusted; the message says why."""


def _matches(pattern: re.Pattern, what: str):
    def check(text: str) -> str:
        if not pattern.fullmatch(text):
            raise ValueError(f"not a {what}")
        return text

    return AfterValidator(check)


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
    prerelease: StrictBool
    security_fix: StrictBool
    files: dict[str, ReleaseFile]

    @model_validator(mode="after")
    def _whole(self) -> Manifest:
        if self.schema_version != 1:
            raise ValueError(f"format {self.schema_version} isn't one this version can read")
        for name in self.files:
            if not _FILE_NAME.fullmatch(name):
                raise ValueError(f"{name!r} isn't a plain file name")
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


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def check_files(directory: Path, manifest: Manifest) -> None:
    """Every file the manifest lists is in `directory`, as it says. Files it doesn't list aren't
    part of the release and are never used, so they aren't looked at."""
    for name, expected in manifest.files.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"{name} is missing, or isn't a plain file")
        if path.stat().st_size != expected.size:
            raise ReleaseError(f"{name} is the wrong size: it isn't the file that was signed")
        if sha256_of(path) != expected.sha256:
            raise ReleaseError(f"{name} has the wrong hash: it isn't the file that was signed")


def read_release(directory: Path, keys: list[PublicKey] | None = None) -> Manifest:
    """A whole release in `directory`: its signature, and then every file against its hash."""
    try:
        data = (directory / MANIFEST).read_bytes()
        signature = (directory / SIGNATURE).read_bytes()
    except OSError as exc:
        raise ReleaseError(f"can't read the release: {exc}") from None
    manifest = read_manifest(data, signature, keys)
    check_files(directory, manifest)
    return manifest

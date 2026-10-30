"""Threat packs kept in the checker's home (plan 4.2): `packs/active/`
holds each pack in force, `packs/retired/` the ones taken out of use
(replaced by a newer version, retired by a person, or signed by a key no
longer trusted), kept so an old analysis can be reproduced. Each pack is
kept with its signature, and checked again whenever it is read."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checker.packs.format import Pack, PackError, read
from checker.packs.signing import SignatureError, verify
from checker.packs.trust import Trusted, trusted_keys

_NAME = re.compile(r"(?P<id>[a-z0-9][a-z0-9-]{0,62})-v(?P<version>[0-9]{1,5})\.yaml")


class StoreError(Exception):
    """A pack that can't be added or found; the message says why."""


@dataclass(frozen=True)
class Stored:
    pack: Pack
    path: Path
    signed_by: Trusted
    sha256: str  # of the pack file as signed


def folder(home: Path, which: str) -> Path:
    path = home / "packs" / which
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _files(directory: Path) -> Iterable[tuple[str, int, Path]]:
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.iterdir()):
        named = _NAME.fullmatch(path.name)
        if named and path.is_file() and not path.is_symlink():
            found.append((named["id"], int(named["version"]), path))
    return found


def _signed(data: bytes, signature: bytes, keys: list[Trusted]) -> Trusted:
    by_id = {k.key.key_id: k for k in keys}
    signed = verify(data, signature, [k.key for k in keys])
    return by_id[signed.key.key_id]


def _load(path: Path, keys: list[Trusted]) -> Stored:
    """A kept pack, its signature checked against the keys trusted now."""
    data = path.read_bytes()
    signature = path.with_name(path.name + ".minisig").read_bytes()
    signer = _signed(data, signature, keys)
    return Stored(read(data), path, signer, hashlib.sha256(data).hexdigest())


def active(home: Path, organization: list[Any]) -> tuple[list[Stored], list[str]]:
    """The packs in force, and why any kept one can't be used now."""
    keys = trusted_keys(home, organization)
    usable, problems = [], []
    for pack_id, version, path in _files(home / "packs" / "active"):
        try:
            stored = _load(path, keys)
        except (OSError, SignatureError, PackError) as exc:
            problems.append(f"{pack_id} version {version}: {exc}")
            continue
        if (stored.pack.id, stored.pack.version) != (pack_id, version):
            problems.append(f"{path.name}: holds {stored.pack.id} version {stored.pack.version}")
            continue
        usable.append(stored)
    return usable, problems


def retired(home: Path) -> list[tuple[str, int, str]]:
    """(id, version, why) for each retired pack."""
    found = []
    for pack_id, version, path in _files(home / "packs" / "retired"):
        why = path.with_name(path.name + ".why")
        found.append((pack_id, version, why.read_text().strip() if why.is_file() else ""))
    return found


def _write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _retire(home: Path, path: Path, why: str) -> None:
    """Move a pack and its signature to retired/, with why and when."""
    target = folder(home, "retired")
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    _write(target / f"{path.name}.why", f"{stamp}: {why}\n".encode())
    signature = path.with_name(path.name + ".minisig")
    if signature.exists():
        os.replace(signature, target / signature.name)
    os.replace(path, target / path.name)


def add(
    home: Path, organization: list[Any], data: bytes, signature: bytes, known_checks: set[str]
) -> tuple[Stored, str]:
    """Check a pack's signature, then its content, then keep it in force;
    an older version of it is retired. Returns it and what happened."""
    keys = trusted_keys(home, organization)
    if not keys:
        raise StoreError(
            "no key is trusted to sign packs yet: NouriLoop's arrive with the first key"
            " list; an organization adds its own with `checker packs trust add`"
        )
    try:
        signer = _signed(data, signature, keys)  # before the content is read at all
    except SignatureError as exc:
        raise StoreError(f"its signature: {exc}") from None
    try:
        pack = read(data)
    except PackError as exc:
        raise StoreError(f"its content:\n{exc}") from None
    unknown = sorted({d.check for d in pack.detections} - known_checks)
    if unknown:
        raise StoreError(
            "its detections name checks this version doesn't have: " + ", ".join(unknown)
        )
    target = folder(home, "active")
    name = f"{pack.id}-v{pack.version}.yaml"
    replaced = []
    for pack_id, version, path in _files(target):
        if pack_id != pack.id:
            continue
        if version == pack.version:
            if path.read_bytes() == data:
                return Stored(
                    pack, path, signer, hashlib.sha256(data).hexdigest()
                ), "already in force"
            raise StoreError(
                f"{pack.id} version {pack.version} is already in force with different content:"
                " a changed pack needs a new version"
            )
        if version > pack.version:
            raise StoreError(f"{pack.id} version {version}, newer, is already in force")
        replaced.append(path)
    path = target / name
    _write(path.with_name(name + ".minisig"), signature)
    _write(path, data)
    for old in replaced:
        _retire(home, old, f"replaced by version {pack.version}")
    outcome = "added" + (
        f", replacing version {_NAME.fullmatch(replaced[0].name)['version']}" if replaced else ""
    )
    return Stored(pack, path, signer, hashlib.sha256(data).hexdigest()), outcome


def retire(home: Path, pack_id: str, why: str) -> list[str]:
    """Take a pack out of use, every version in force; returns their names."""
    done = []
    for found_id, _, path in _files(home / "packs" / "active"):
        if found_id == pack_id:
            _retire(home, path, why)
            done.append(path.name)
    if not done:
        raise StoreError(f"no pack {pack_id!r} is in force")
    return done


def sweep(home: Path, organization: list[Any]) -> list[str]:
    """Retire every pack in force whose signature no key trusted now
    checks out (its key revoked, or an organization key removed)."""
    keys = trusted_keys(home, organization)
    done = []
    for _, _, path in _files(home / "packs" / "active"):
        try:
            _load(path, keys)
        except SignatureError as exc:
            _retire(home, path, f"its signature is no longer trusted: {exc}")
            done.append(path.name)
        except (OSError, PackError):
            continue  # reported by active(); a damaged file isn't a revocation
    return done
